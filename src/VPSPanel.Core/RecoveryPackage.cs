using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Generators;

namespace VPSPanel.Core;

public sealed record PackageFile(string Name, long Length, string Sha256);
public sealed record PackageManifest(int Format, string Architecture, string XrayVersion, string RelayVersion,
    DateTimeOffset Created, PackageFile[] Files);
public sealed record OpenPackage(PackageManifest Manifest, Dictionary<string, byte[]> Files)
{
    public T Json<T>(string name) => JsonSerializer.Deserialize<T>(Files[name]) ?? throw new InvalidDataException();
}

public static class RecoveryPackage
{
    public const string KernelVersion = "26.10.31";
    public const string RelayVersion = "1.4.0";
    public static readonly IReadOnlyList<string> Required = Array.AsReadOnly(new[] {
        "source.json","portable.json","panel.json","plan.json","geoip.dat","geosite.dat","relay-geoip.dat","relay-geosite.dat","xray","relay" });
    private static readonly byte[] Magic = "VPSPKG01"u8.ToArray();
    private const int Chunk = 1024 * 1024;
    private const int MaxFile = 256 * Chunk;
    private const long MaxTotal = 640L * Chunk;

    private static byte[] Key(string password, byte[] header)
    {
        if(string.IsNullOrEmpty(password) || Encoding.UTF8.GetByteCount(password)>1024)
            throw new PanelException("备份口令为空或过长。");
        var bytes=Encoding.UTF8.GetBytes(password);
        try { return SCrypt.Generate(bytes, header[8..24], 1<<17, 8, 1, 32); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public static string ElfArchitecture(byte[] file)
    {
        if(file.Length<64 || !file.AsSpan(0,4).SequenceEqual(new byte[]{127,69,76,70}) || file[4]!=2 || file[5]!=1)
            throw new PanelException("安装件应为 Linux 64 位 ELF 可执行文件。");
        return BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(18)) switch{
            62=>"x86_64",183=>"aarch64",_=>throw new PanelException("安装件架构不受支持。")};
    }
    private static void Validate(PackageManifest m)
    {
        if(m.Format!=1 || m.Architecture is not ("x86_64" or "aarch64") ||
            m.XrayVersion!=KernelVersion || m.RelayVersion!=RelayVersion || m.Files==null ||
            !m.Files.Select(f=>f.Name).SequenceEqual(Required) ||
            m.Files.Any(f=>f.Length<=0 || f.Length>MaxFile || f.Sha256.Length!=64 || !f.Sha256.All(Uri.IsHexDigit)) ||
            m.Files.Sum(f=>f.Length)>MaxTotal)throw new PanelException("版本清单不兼容、缺少文件或超过大小限制。");
    }

    public static PackageManifest Export(string path,string password,string confirmation,Dictionary<string,byte[]> files)
    {
        if(password!=confirmation) throw new PanelException("两次输入的备份口令不一致。");
        if(Required.Any(n=>!files.ContainsKey(n)))throw new PanelException("恢复材料不完整。");
        string arch=ElfArchitecture(files["xray"]);
        if(ElfArchitecture(files["relay"])!=arch)throw new PanelException("Xray 与 Relay 的目标架构不同。");
        var manifest=new PackageManifest(1,arch,KernelVersion,RelayVersion,DateTimeOffset.UtcNow,
            Required.Select(name=>new PackageFile(name,files[name].LongLength,Convert.ToHexString(SHA256.HashData(files[name])))).ToArray());
        Validate(manifest);
        path=Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{
            var header=new byte[32];Magic.CopyTo(header,0);RandomNumberGenerator.Fill(header.AsSpan(8));
            var key=Key(password,header);
            try{
                using var gcm=new AesGcm(key,16);
                using var output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None);
                output.Write(header);
                byte[] encoded=JsonSerializer.SerializeToUtf8Bytes(manifest);
                Span<byte> length=stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(length,encoded.Length);output.Write(length);
                var ciphertext=new byte[Chunk];var tag=new byte[16];uint frame=0;
                void Write(ReadOnlySpan<byte> value){
                    gcm.Encrypt(Nonce(header,frame++),value,ciphertext.AsSpan(0,value.Length),tag,header);
                    output.Write(ciphertext,0,value.Length);output.Write(tag);
                }
                Write(encoded);
                foreach(var f in manifest.Files){
                    var data=files[f.Name];
                    for(int offset=0;offset<data.Length;offset+=Chunk)Write(data.AsSpan(offset,Math.Min(Chunk,data.Length-offset)));
                }
                output.Flush(true);
            }finally{CryptographicOperations.ZeroMemory(key);}
            Read(temp,password,(_,_)=>{}); // Re-open the finished ciphertext and verify every byte before replacement.
            File.Move(temp,path,true);
            return manifest;
        }finally{File.Delete(temp);}
    }
    private static byte[] Nonce(byte[] header,uint index){
        var nonce=new byte[12];header.AsSpan(24,8).CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8),index);return nonce;
    }
    public static OpenPackage Open(string path,string password,params string[] names)
    {
        var selected=new Dictionary<string,byte[]>();
        var manifest=Read(path,password,(f,data)=>{if(names.Contains(f.Name))selected.Add(f.Name,data.ToArray());});
        return new(manifest,selected);
    }
    public static PackageManifest Read(string path,string password,Action<PackageFile,ReadOnlyMemory<byte>> consume)
    {
        using var input=File.OpenRead(path);
        try{
            if(input.Length>MaxTotal+Chunk)throw new InvalidDataException();
            byte[] header=new byte[32];input.ReadExactly(header);
            if(!header.AsSpan(0,8).SequenceEqual(Magic))throw new InvalidDataException();
            byte[] key=Key(password,header);
            try{
                using var gcm=new AesGcm(key,16);uint frame=0;
                byte[] cipher=new byte[Chunk],tag=new byte[16];
                void Decrypt(Span<byte> dest){
                    input.ReadExactly(cipher.AsSpan(0,dest.Length));input.ReadExactly(tag);
                    gcm.Decrypt(Nonce(header,frame++),cipher.AsSpan(0,dest.Length),tag,dest,header);
                }
                Span<byte> length=stackalloc byte[4];input.ReadExactly(length);
                int n=BinaryPrimitives.ReadInt32BigEndian(length);
                if(n is <1 or >65536)throw new InvalidDataException();
                byte[] json=new byte[n];Decrypt(json);
                var m=JsonSerializer.Deserialize<PackageManifest>(json)??throw new InvalidDataException();Validate(m);
                foreach(var f in m.Files){
                    var data=ArrayPool<byte>.Shared.Rent((int)f.Length);
                    try{
                        for(int i=0;i<f.Length;i+=Chunk)Decrypt(data.AsSpan(i,(int)Math.Min(Chunk,f.Length-i)));
                        var memory=data.AsMemory(0,(int)f.Length);
                        if(!Convert.ToHexString(SHA256.HashData(memory.Span)).Equals(f.Sha256,StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException();
                        if(f.Name is "xray" or "relay" && ElfArchitecture(data)!=m.Architecture)
                            throw new PanelException("恢复包的安装件架构与清单不一致。");
                        consume(f,memory);
                    }finally{ArrayPool<byte>.Shared.Return(data,clearArray:true);}
                }
                if(input.ReadByte()!=-1)throw new InvalidDataException();
                return m;
            }finally{CryptographicOperations.ZeroMemory(key);}
        }catch(Exception e) when(e is CryptographicException or EndOfStreamException or InvalidDataException or JsonException or NullReferenceException){
            throw new PanelException("备份口令错误或文件损坏，完整性校验失败。");
        }
    }
}
