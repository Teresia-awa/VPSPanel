"""Two independent HY2 peers and an actual pinned Xray, inside a loopback-only namespace."""
import concurrent.futures, contextlib, copy, json, os, secrets, shutil, socket, socketserver
import signal, ssl, struct, subprocess, sys, tempfile, threading, time
from pathlib import Path

PEERS = {"A": 23101, "B": 23101}
BACKENDS = {"A": 23201, "B": 23202, "D": 23203}
delay = {name: .015 for name in BACKENDS}
alive = dict.fromkeys(BACKENDS, True)
address = "127.0.0.1"
api, relay_port, entry_port = 23301, 23302, 23303
unlimited = dict(Enabled=False, Upload=0, Download=0)
dns_address = "192.0.2.53"
dns_port = 23304
doh_ports = {"A": 23305, "B": 23306, "D": 23307}
backup_doh_port = 23308

def readn(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n-len(data))
        if not part: raise EOFError("stream ended")
        data.extend(part)
    return bytes(data)

class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s, label = self.request, self.server.label
        try:
            while True:
                op = readn(s, 1)
                if op == b"G":
                    data = b"G"
                    while b"\r\n\r\n" not in data: data += readn(s, 1)
                    time.sleep(delay[label])
                    s.sendall(b"HTTP/1.1 "+(b"204 No Content" if alive[label] else b"503 Unavailable")+b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    return
                if op == b"?": s.sendall(label.encode())
                elif op in (b"U", b"D"):
                    size = struct.unpack("!I", readn(s,4))[0]
                    if op == b"U": readn(s,size); s.sendall(label.encode())
                    else: s.sendall(label.encode()*size)
                else: return
        except (EOFError,OSError): pass

def dns_answer(query, answer):
    end = query.index(0, 12) + 5
    return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:end] +
            bytes.fromhex("c00c00010001000000000004") + socket.inet_aton(answer))


def dns_labels(query):
    pos = 12
    while query[pos]:
        length = query[pos]; pos += 1
        yield query[pos:pos+length]
        pos += length

class PlainDnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request
        try:
            query = readn(stream, struct.unpack("!H", readn(stream, 2))[0])
            answer = dns_answer(query, "198.51.100.4")
            stream.sendall(struct.pack("!H", len(answer)) + answer)
        except (EOFError, OSError):
            pass


class DohHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Minimal HTTP/2 DoH server, with a distinct A answer per exit.
        def frame(kind, flags, stream, payload=b""):
            return struct.pack("!I", len(payload))[1:] + bytes([kind, flags]) + struct.pack("!I", stream) + payload

        try:
            with self.server.tls.wrap_socket(self.request, server_side=True) as stream:
                assert stream.selected_alpn_protocol() == "h2"
                assert readn(stream, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                stream.sendall(frame(4, 0, 0))
                bodies = {}
                while True:
                    header = readn(stream, 9)
                    kind, flags, stream_id = struct.unpack("!BBI", header[3:])
                    data = readn(stream, int.from_bytes(header[:3], "big"))
                    if kind == 4 and not flags & 1:
                        stream.sendall(frame(4, 1, 0))
                    if kind == 0:
                        bodies.setdefault(stream_id, bytearray()).extend(data)
                        if flags & 1:
                            query = bodies.pop(stream_id)
                            name = ".".join(part.decode() for part in dns_labels(query)).lower()
                            self.server.queries.append(name)
                            answer = dns_answer(query, self.server.records.get(name,self.server.answer))
                            mime = b"application/dns-message"
                            headers = b"\x88\x0f\x10" + bytes([len(mime)]) + mime
                            stream.sendall(frame(1, 4, stream_id, headers) + frame(0, 1, stream_id, answer))
        except (EOFError, OSError):
            pass


def backend(stack, name, port):
    server = Server((address,port),Handler); server.label=name
    threading.Thread(target=server.serve_forever,daemon=True).start()
    stack.callback(server.server_close)
    udp=stack.enter_context(socket.socket(socket.AF_INET,socket.SOCK_DGRAM))
    udp.bind((address,port))
    def echo():
        try:
            while True:
                data,source=udp.recvfrom(65535)
                udp.sendto(name.encode()+data,source)
        except OSError: pass
    threading.Thread(target=echo,daemon=True).start()

def dump(path, data): Path(path).write_text(json.dumps(data))
def load(path): return json.loads(Path(path).read_text())
def wait(check, timeout=16):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            value=check()
            if value: return value
        except (FileNotFoundError,ConnectionRefusedError): pass
        time.sleep(.08)
    raise AssertionError("timed out waiting for "+check.__name__)

def dest(host,port):
    data=host.encode()
    return bytes([3,len(data)])+data+struct.pack("!H",port)

def socks(target="fixed.invalid", cmd=1, port=relay_port, target_port=23880):
    s=socket.create_connection((address,port),3);s.settimeout(9)
    s.sendall(b"\x05\x01\x00");assert readn(s,2)==b"\x05\x00"
    s.sendall(bytes([5,cmd,0])+(dest(target,target_port) if cmd==1 else bytes([1,0,0,0,0,0,0])))
    response=readn(s,4)
    n={1:4,4:16}.get(response[3]); readn(s,n if n is not None else readn(s,1)[0])
    bound=struct.unpack("!H",readn(s,2))[0]
    if response[1]: s.close(); raise ConnectionError("explicit SOCKS failure "+str(response[1]))
    return s,bound

def marker(s): s.sendall(b"?");return readn(s,1).decode()
def route(target,port=relay_port):
    s,_=socks(target,port=port)
    with s: return marker(s)

def udp_flow(stack,entry=relay_port,target="fixed.invalid",target_port=23880):
    control,port=socks(cmd=3,port=entry);stack.enter_context(control)
    s=stack.enter_context(socket.socket(socket.AF_INET,socket.SOCK_DGRAM));s.settimeout(3)
    header=bytes(3)+dest(target,target_port)
    def ping():
        s.sendto(header+b"-UDP",(address,port))
        result=s.recv(512)
        return result[-5:].decode()
    return ping

def run(xray,binary):
    if [name for _,name in socket.if_nameindex()]!=["lo"]:raise RuntimeError("requires a separate network namespace")
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    assert os.readlink("/proc/self/ns/mnt") != os.readlink("/proc/1/ns/mnt")
    subprocess.run(["ip","link","set","lo","up"],check=True)
    subprocess.run(["ip","addr","add",dns_address+"/32","dev","lo"],check=True)
    if "26.10.31 " not in subprocess.check_output([xray,"version"],text=True):raise ValueError("expected Xray 26.10.31")
    with tempfile.TemporaryDirectory(prefix="panel-stage3-") as tmp, contextlib.ExitStack() as stack:
        work=Path(tmp); os.chdir(work)
        binary=str(work/"relay");shutil.copyfile(sys.argv[2],binary);os.chmod(binary,0o700)
        hosts=work/"hosts"
        hosts.write_text("127.0.0.1 localhost\n127.0.0.2 a.lab.invalid\n127.0.0.3 b.lab.invalid\n")
        subprocess.run(["mount","--bind",str(hosts),"/etc/hosts"],check=True)
        stack.callback(subprocess.run,["umount","/etc/hosts"],check=True)
        for name,p in BACKENDS.items():backend(stack,name,p)
        log=stack.enter_context(open("process.log","w+"))
        def stop(p):
            if p.poll() is None:
                p.terminate()
                try:p.wait(4)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        commands=work/"commands"
        commands.mkdir()
        env=dict(os.environ, SSL_CERT_FILE=str(work/"tls.pem"), XRAY_LAB_BINARY=xray, XRAY_LOCATION_ASSET=str(work),
                 PATH=str(commands)+os.pathsep+os.environ["PATH"])
        def start(args):
            p=subprocess.Popen(args, stdout=log, stderr=log, env=env)
            stack.callback(stop,p)
            return p
        def start_xray(file):
            p=start([xray,"run","-c",file])
            if file=="xray.json": Path("core.pid").write_text(str(p.pid))
            return p
        systemctl=commands/"systemctl"
        systemctl.write_text("""#!/usr/bin/python3
import os, signal, socket, subprocess, sys, time
from pathlib import Path
assert sys.argv[1:]==["restart","xray-lab.service"]
pid=Path("core.pid")
try:
    os.kill(int(pid.read_text()), signal.SIGTERM)
except ProcessLookupError:
    pass
for _ in range(50):
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1",23301)) != 0: break
    time.sleep(.04)
with open("process.log","ab") as output:
    child=subprocess.Popen([os.environ["XRAY_LAB_BINARY"],"run","-c","xray.json"],
                           stdout=output,stderr=output,start_new_session=True)
pid.write_text(str(child.pid))
""")
        systemd_run=commands/"systemd-run"
        systemd_run.write_text("""#!/usr/bin/python3
import json,sys
from pathlib import Path
assert "--on-active=90s" in sys.argv and sys.argv[-3]=="recover-dns"
Path("watchdog.json").write_text(json.dumps(sys.argv[-4:]))
""")
        for command in (systemctl,systemd_run): command.chmod(0o700)
        def stop_restarted_core():
            pid=work/"core.pid"
            if pid.exists():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(pid.read_text()),signal.SIGTERM)
        stack.callback(stop_restarted_core)
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout","tls.key","-out","tls.pem","-days","1","-subj","/CN=lab.invalid","-addext","subjectAltName=DNS:lab.invalid,DNS:check.lab.invalid,IP:"+dns_address],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cert=str(work/"tls.pem");auth=secrets.token_hex(18)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert,"tls.key")
        tls.set_alpn_protocols(["h2"])
        for i,(name,port) in enumerate(doh_ports.items(), 1):
            server=Server((address if name!="D" else dns_address,port),DohHandler)
            server.tls=tls
            server.records, server.queries = {}, []
            server.answer="198.51.100."+str(i)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            stack.callback(server.server_close)
        backup = Server((dns_address, backup_doh_port), DohHandler)
        backup.queries = []
        backup.records = {"a.lab.invalid":"127.0.0.2","b.lab.invalid":"127.0.0.3","spare.lab.invalid":"127.0.0.3",
                          "new.lab.invalid":"127.0.0.2","direct.invalid":"127.0.0.1","check.lab.invalid":"127.0.0.1"}
        backup.tls, backup.answer = tls, "198.51.100.5"
        threading.Thread(target=backup.serve_forever, daemon=True).start()
        stack.callback(backup.server_close)
        plain = Server((dns_address, 53), PlainDnsHandler)
        threading.Thread(target=plain.serve_forever, daemon=True).start()
        stack.callback(plain.server_close)
        def freedom(tag,redirect=None):
            opts=dict(finalRules=[dict(action="allow",ip=["127.0.0.0/8", dns_address]),dict(action="block")])
            if redirect:opts["redirect"]=address+":"+str(redirect)
            return dict(tag=tag,protocol="freedom",settings=opts)
        def outgoing(name):
            return dict(protocol="hysteria",settings=dict(version=2,address=name.lower()+".lab.invalid",port=PEERS[name]),
                streamSettings=dict(network="hysteria",security="tls",tlsSettings=dict(serverName="lab.invalid",alpn=["h3"],certificates=[dict(usage="verify",certificateFile=cert)]),hysteriaSettings=dict(version=2,auth=auth)))
        health_ports = {name: 23420+i for i,name in enumerate(BACKENDS)}
        health_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        health_tls.load_cert_chain(cert,"tls.key")
        for name,port in health_ports.items():
            health = Server((address,port),Handler)
            health.label = name
            health.socket = health_tls.wrap_socket(health.socket,server_side=True)
            threading.Thread(target=health.serve_forever,daemon=True).start()
            stack.callback(health.server_close)
        for name,p in PEERS.items():
            ingress=dict(listen="127.0.0."+("2" if name=="A" else "3"),port=p,protocol="hysteria",settings=dict(version=2,users=[dict(auth=auth)]),streamSettings=dict(network="hysteria",security="tls",tlsSettings=dict(alpn=["h3"],certificates=[dict(certificateFile=cert,keyFile=str(work/"tls.key"))]),hysteriaSettings=dict(version=2)))
            doh_rule=dict(type="field",ip=[dns_address],outboundTag="doh")
            file=name+".json";dump(file,dict(inbounds=[ingress],outbounds=[freedom("backend",BACKENDS[name]),freedom("doh",doh_ports[name]),freedom("health",health_ports[name])],
                                             routing=dict(rules=[doh_rule,dict(type="field",domain=["full:check.lab.invalid"],outboundTag="health")])))
            start_xray(file)
        base=dict(api=dict(tag="api",listen=address+":"+str(api),services=["HandlerService","RoutingService"]),
            inbounds=[dict(tag="entry",protocol="socks",listen=address,port=entry_port,settings=dict(udp=True))],
            outbounds=[dict(tag="closed",protocol="blackhole"),dict(tag="relay",protocol="socks",settings=dict(servers=[dict(address=address,port=relay_port)]))],
            routing=dict(rules=[dict(type="field",inboundTag=["entry"],outboundTag="relay")]))
        base["dns"]=dict(tag="internal-doh",servers=["https://"+dns_address+":"+str(doh_ports["D"])+"/dns-query"],
                         disableCache=True,queryStrategy="UseIPv4")
        base["inbounds"].append(dict(tag="dns-test",listen=address,port=dns_port,protocol="tunnel",
                                     settings=dict(address=dns_address,port=53,network="tcp")))
        base["outbounds"].extend([dict(tag="dns-test",protocol="dns"),dict(tag="old-doh",protocol="freedom")])
        base["routing"]["rules"].extend([dict(type="field",inboundTag=["dns-test"],outboundTag="dns-test"),
                                         dict(type="field",inboundTag=["internal-doh"],outboundTag="old-doh")])
        dump("xray.json",base)
        dump("relay.json",dict(Xray=xray,ApiPort=api,ListenPort=relay_port,CheckUrl="http://127.0.0.1:"+str(BACKENDS["D"])+"/ok",ProbeSeconds=1,
                              DirectDnsFallback="https://"+dns_address+":"+str(backup_doh_port)+"/dns-query"))
        def listening(port):
            with socket.create_connection((address,port),.15):return True
        def servers():
            x=start_xray("xray.json");wait(lambda:listening(api))
            r=start([binary,"serve",tmp]);wait(lambda:listening(relay_port))
            return x,r
        def submit(plan,ok=True,command="submit",restart=False):
            dump("input.json",plan)
            if restart:
                rid=secrets.token_hex(16)
                dump("lab-request.json",dict(Id=rid,Plan=plan,XrayService="xray-lab"))
                os.replace("lab-request.json","request.json")
            elif command=="submit-existing":rid=subprocess.check_output([binary,command,tmp,"-"],input=json.dumps(plan),text=True).strip()
            else:rid=subprocess.check_output([binary,command,tmp,"input.json"],text=True).strip()
            def result():
                data=load("result.json")
                return data if data["Id"]==rid else None
            out=wait(result,100)
            assert out["Success"]==ok,out
            wait(lambda:not Path("request.json").exists())
        def resolve(label):
            name=[label.encode(),b"invalid"]
            message=struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            message+=b"".join(bytes([len(part)])+part for part in name)+b"\x00\x00\x01\x00\x01"
            with socket.create_connection((address,dns_port),3) as stream:
                stream.settimeout(8)
                stream.sendall(struct.pack("!H",len(message))+message)
                try: answer=readn(stream,struct.unpack("!H",readn(stream,2))[0])
                except (EOFError,TimeoutError): return None
            return socket.inet_ntoa(answer[-4:]) if answer[6:8]==b"\x00\x01" else None
        def fixed(id, entry, to):return dict(Id=id,Name=id,Group=None,Entries=[entry],Action="Fixed",Enabled=True,Exit=to)
        policy=dict(Groups=[],Rules=[fixed("pinned","full:fixed.invalid","A"),fixed("pinnedB","full:other.invalid","B")])
        exits=[dict(Id=n,Name=n,Direct=n=="D",Enabled=True,Limit=unlimited,Outbound=freedom("direct") if n=="D" else outgoing(n)) for n in BACKENDS]
        plan=dict(Policy=policy,Exits=exits,Total=unlimited)
        def status():return {l["Id"]:l for l in load("status.json")["Links"]}
        def expect_failure(host):
            try:route(host)
            except ConnectionError as e:assert "explicit SOCKS failure" in str(e);return
            raise AssertionError("expected fail-closed connection")
        try:
            xr,relay=servers();submit(plan)
            wait(lambda: len(status())==3 and all(l["Healthy"] for l in status().values()))
            dns_plan=copy.deepcopy(plan)
            dns_plan["FollowHealthyDns"]=True
            dns_plan["Policy"]["Rules"].append(dict(fixed("vpspanel:default","unmatched:*","B"),Action="Direct",Exit=None))
            alive["B"]=False
            wait(lambda:not status()["B"]["Healthy"])
            submit(dns_plan)
            assert resolve("healthy-a")=="198.51.100.1"
            alive["B"]=True
            wait(lambda:status()["B"]["Healthy"])
            alive["A"]=False
            wait(lambda:not status()["A"]["Healthy"])
            assert resolve("failover-b")=="198.51.100.2"
            alive["B"]=False
            wait(lambda:not status()["B"]["Healthy"])
            assert status()["D"]["Healthy"] and resolve("all-failed") is None
            for rejected in ("Direct", "Plaintext"):
                candidate = dict(dns_plan, DnsOnFailure=rejected)
                submit(candidate, ok=False)
                assert resolve("reject-"+rejected.lower()) is None
            alive["B"]=True
            wait(lambda:status()["B"]["Healthy"])
            assert resolve("proxy-restored")=="198.51.100.2"
            submit(plan)
            assert resolve("legacy-restored")=="198.51.100.3"
            alive["A"]=alive["B"]=True
            wait(lambda:all(status()[n]["Healthy"] and status()[n]["FailureRate"]<.1 for n in ("A","B")))
            direct_before = status()["D"]["Assigned"]
            print("encrypted DNS: real DoH, proxy failover, reject including legacy policies, recovery and rollback: passed",flush=True)
            assert route("fixed.invalid",entry_port)=="A"
            assert route("other.invalid",entry_port)=="B"
            with contextlib.ExitStack() as flows:assert udp_flow(flows,entry_port)()=="A-UDP"
            normal=[route("default.invalid") for _ in range(40)]
            assert "A" in normal and "B" in normal
            print("baseline A/B: %d/%d"%(normal.count("A"),normal.count("B")),flush=True)
            delay["A"]=.35
            wait(lambda:status()["A"]["LatencyMs"]>140)
            results=[route("default.invalid") for _ in range(40)]
            assert results.count("B")>=30,results
            print("congestion: new connections B=%d/40"%results.count("B"),flush=True)
            alive["A"]=False;wait(lambda:not status()["A"]["Healthy"])
            assert route("default.invalid")=="B";expect_failure("fixed.invalid")
            alive["B"]=False;wait(lambda:not status()["B"]["Healthy"])
            expect_failure("default.invalid");assert status()["D"]["Healthy"] and status()["D"]["Assigned"]==direct_before
            alive["A"]=alive["B"]=True;delay["A"]=.015
            wait(lambda:status()["A"]["Healthy"] and status()["B"]["Healthy"])
            assert route("fixed.invalid")=="A"
            print("single failure, bound failure, all-failed, recovery: passed",flush=True)
            default_plan=copy.deepcopy(plan)
            fallback=fixed("vpspanel:default","unmatched:*","B")
            default_plan["Policy"]["Rules"].append(fallback)
            submit(default_plan)
            with contextlib.ExitStack() as streams:
                tcp=streams.enter_context(socks("127.0.0.1",port=entry_port,target_port=BACKENDS["D"])[0])
                udp=udp_flow(streams,entry_port,"127.0.0.1",BACKENDS["D"])
                assert marker(tcp)=="B" and udp()=="B-UDP" and route("fixed.invalid",entry_port)=="A"
                alive["B"]=False;wait(lambda:not status()["B"]["Healthy"])
                expect_failure("default.invalid")
                alive["B"]=True;wait(lambda:status()["B"]["Healthy"])
                fallback.update(Action="Direct",Exit=None)
                submit(default_plan)
                with socks("127.0.0.1",port=entry_port,target_port=BACKENDS["D"])[0] as direct:
                    assert marker(direct)=="D" and udp_flow(streams,entry_port,"127.0.0.1",BACKENDS["D"])()=="D-UDP"
                assert marker(tcp)=="B" and udp()=="B-UDP" and route("fixed.invalid",entry_port)=="A"
            submit(plan)
            print("unmatched default: fixed, fail-closed, direct, TCP/UDP session affinity, explicit priority, auto reset: passed",flush=True)
            failure_plan=copy.deepcopy(plan)
            failure_rules=failure_plan["Policy"]["Rules"]
            failure_rules.append(fixed("pinned-local","ip:127.0.0.1","B"))
            failure=fixed("vpspanel:unavailable","unavailable:*","A")
            failure_rules.append(failure)
            submit(failure_plan)
            with contextlib.ExitStack() as flows:
                old_tcp=flows.enter_context(socks("other.invalid",port=entry_port)[0])
                old_udp=udp_flow(flows,entry_port,"other.invalid")
                assert marker(old_tcp)=="B" and old_udp()=="B-UDP"
                peer_b=next(e for e in failure_plan["Exits"] if e["Id"]=="B")
                peer_b["Enabled"]=False;submit(failure_plan)
                assert route("other.invalid",entry_port)=="A" and udp_flow(flows,entry_port,"other.invalid")()=="A-UDP"
                assert marker(old_tcp)=="B" and old_udp()=="B-UDP"
                failure.update(Action="Direct",Exit=None);submit(failure_plan)
                with socks("127.0.0.1",port=entry_port,target_port=BACKENDS["D"])[0] as direct:
                    assert marker(direct)=="D" and udp_flow(flows,entry_port,"127.0.0.1",BACKENDS["D"])()=="D-UDP"
                failure.update(Action="Auto");submit(failure_plan)
                assert route("other.invalid",entry_port)=="A"
                alive["A"]=False;wait(lambda:not status()["A"]["Healthy"])
                expect_failure("other.invalid")
                alive["A"]=True;wait(lambda:status()["A"]["Healthy"])
                failure.update(Entries=["unavailable:default"])
                fallback=fixed("vpspanel:default","unmatched:*","B");failure_rules.append(fallback)
                submit(failure_plan);expect_failure("other.invalid")
                fallback["Exit"]="A";submit(failure_plan)
                assert route("other.invalid",entry_port)=="A"
                peer_b["Enabled"]=True;submit(failure_plan)
                # The status file is sampled once a second; first observe the newly enabled B.
                wait(lambda:status()["B"]["Healthy"])
                alive["B"]=False;wait(lambda:not status()["B"]["Healthy"])
                assert route("other.invalid",entry_port)=="A"
                alive["B"]=True;wait(lambda:status()["B"]["Healthy"])
                assert route("other.invalid",entry_port)=="B"
            submit(plan)
            print("exit failover: disabled/unhealthy, fixed, direct, auto, follow-default, double failure, TCP/UDP affinity and recovery: passed",flush=True)
            with contextlib.ExitStack() as old:
                sock=old.enter_context(socks()[0]);ping=udp_flow(old)
                assert marker(sock)=="A" and ping()=="A-UDP"
                before=load("committed.json")
                plan["Exits"][0]["Outbound"]=outgoing("B")
                submit(plan)
                assert route("fixed.invalid")=="B" and marker(sock)=="A" and ping()=="A-UDP"
                with contextlib.ExitStack() as new:assert udp_flow(new)()=="B-UDP"
                # A second change completes while the original sockets still hold generation one.
                plan["Exits"][0]["Outbound"]=outgoing("A");submit(plan)
                assert route("fixed.invalid")=="A" and ping()=="A-UDP"
                plan["Exits"][0]["Outbound"]=outgoing("B");submit(plan,command="submit-existing")
                assert route("fixed.invalid")=="B" and marker(sock)=="A"
                retired=before["Lanes"][0]["Tag"]
                assert retired not in Path("xray.json").read_text()
            def removed():
                out=subprocess.check_output([xray,"api","lso","--server="+address+":"+str(api)],text=True)
                return retired not in out
            wait(removed)
            print("domain switch: old TCP/UDP A; new TCP/UDP B; retired handler removed",flush=True)
            previous=Path("xray.json").read_bytes()
            invalid=copy.deepcopy(plan);invalid["Exits"][0]["Outbound"]["settings"]["port"]=99999
            submit(invalid,False);assert Path("xray.json").read_bytes()==previous and route("fixed.invalid")=="B"
            broken=copy.deepcopy(plan);broken["Exits"][0]["Outbound"]["settings"]["port"]=23999
            submit(broken,False);assert Path("xray.json").read_bytes()==previous and route("fixed.invalid")=="B"
            # Deny replacement of the committed state after Xray's dynamic operations succeed.
            shutil.copyfile("committed.json","mount-state")
            subprocess.run(["mount","--bind","mount-state","committed.json"],check=True)
            try:
                attempted=copy.deepcopy(plan);attempted["Exits"][0]["Outbound"]=outgoing("A")
                submit(attempted,False)
            finally:subprocess.run(["umount","committed.json"],check=True)
            assert Path("xray.json").read_bytes()==previous and route("fixed.invalid")=="B"
            assert not Path("transaction.json").exists()
            extra=copy.deepcopy(plan);c=copy.deepcopy(extra["Exits"][1]);c["Id"]="C";extra["Exits"].append(c)
            submit(extra);assert len(load("committed.json")["Lanes"])==4
            submit(plan);assert len(load("committed.json")["Lanes"])==3
            stop(relay);stop(xr);xr,relay=servers()
            wait(lambda:status()["A"]["Healthy"] and status()["B"]["Healthy"] and route("fixed.invalid")=="B",25)
            print("static & probe rejection, disk failure rollback, add/remove and restart: passed",flush=True)
            size=160000
            def timed_pair(sockets,op):
                def transfer(s):
                    s.sendall(op+struct.pack("!I",size))
                    if op==b"U":s.sendall(bytes(size));readn(s,1)
                    else:readn(s,size)
                start_at=time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(2) as workers:list(workers.map(transfer,sockets))
                return time.monotonic()-start_at
            for mode in ("exit","overall"):
                speed_targets=["fixed.invalid","fixed.invalid" if mode=="exit" else "other.invalid"]
                with contextlib.ExitStack() as streams:
                    first=streams.enter_context(socks(speed_targets[0])[0])
                    cap=dict(Enabled=True,Upload=1,Download=2)
                    update=dict(Policy=policy,Total=cap if mode=="overall" else unlimited,Settings=[dict(Id="A",Enabled=True,Limit=cap if mode=="exit" else unlimited)])
                    submit(update,command="submit-policy");second=streams.enter_context(socks(speed_targets[1])[0]);pair=[first,second]
                    up=timed_pair(pair,b"U");down=timed_pair(pair,b"D")
                    assert 2.2<up<5 and 1<down<3,(mode,up,down)
                    update["Total"]=unlimited;update["Settings"][0]["Limit"]=unlimited;submit(update,command="submit-policy")
                    fast=timed_pair(pair,b"D");assert fast<.8,fast
                    print("%s shared: upload %.2fs, download %.2fs, disabled %.2fs"%(mode,up,down,fast),flush=True)
            previous=load("committed.json")["Plan"]
            no_dns=load("xray.json")
            no_dns.pop("dns",None)
            dump("xray.json",no_dns)
            subprocess.run(["systemctl","restart","xray-lab.service"],env=env,check=True)
            wait(lambda:listening(api))
            managed=copy.deepcopy(previous)
            managed.update(FollowHealthyDns=True,
                           BootstrapDohResolvers=["https+local://"+dns_address+":"+str(backup_doh_port)+"/dns-query"],
                           ManagedDohResolvers=["https://"+dns_address+":"+str(doh_ports["D"])+"/dns-query"])
            submit(managed,ok=False)
            assert "dns" not in load("xray.json")
            managed["Exits"][0]["Aliases"]=["spare.lab.invalid"]
            managed["Policy"]["Rules"].insert(0,dict(fixed("direct-name","full:direct.invalid","A"),Action="Direct",Exit=None))
            # Switch the real probe target to a TLS origin accessible independently on each lane.
            stop(relay)
            options=load("relay.json")
            options["CheckUrl"]="https://check.lab.invalid:"+str(health_ports["D"])+"/ok"
            dump("relay.json",options)
            relay=start([binary,"serve",tmp]);wait(lambda:listening(relay_port))
            # Mount a private resolver file in the fixture only. Every OS lookup hits a counted sink.
            (work/"resolver.fixture").write_text("nameserver 127.0.0.1\\noptions timeout:1 attempts:1\\n")
            subprocess.run(["mount","--bind",str(work/"resolver.fixture"),"/etc/resolv.conf"],check=True)
            leaks=[]
            class OsDnsSink(socketserver.BaseRequestHandler):
                def handle(self):
                    leaks.append(time.monotonic())
            sink=socketserver.ThreadingUDPServer((address,53),OsDnsSink)
            threading.Thread(target=sink.serve_forever,daemon=True).start()
            stack.callback(sink.server_close)
            saved_hosts=hosts.read_text()
            hosts.write_text("127.0.0.1 localhost\n")
            assert subprocess.run(["getent","ahosts","spare.lab.invalid"],stdout=subprocess.DEVNULL).returncode != 0
            assert leaks, "resolver sink was not exercised"
            managed["BootstrapDohResolvers"].insert(0,"https+local://192.0.2.77/dns-query")
            submit(managed,restart=True)
            wait(lambda:all(row["Healthy"] for row in status().values()))
            leaks.clear()
            assert "check.lab.invalid" in backup.queries
            direct_socket,_=socks("direct.invalid",port=entry_port,target_port=BACKENDS["D"])
            with direct_socket: assert marker(direct_socket)=="D"
            assert resolve("direct")=="127.0.0.1"
            assert "direct.invalid" in backup.queries
            assert resolve("new-profile") in ("198.51.100.1","198.51.100.2")
            assert "new-profile.invalid" not in backup.queries
            spare=outgoing("B");spare["settings"]["address"]="spare.lab.invalid"
            prepared=subprocess.run([binary,"prepare-probe",tmp],input=json.dumps(spare),text=True,
                                    env=env,capture_output=True,check=True)
            assert json.loads(prepared.stdout)["settings"]["address"]=="127.0.0.3"
            before_pid=Path("core.pid").read_text()
            swapped=copy.deepcopy(managed)
            old_node=swapped["Exits"][0]["Outbound"]["settings"]["address"]
            swapped["Exits"][0].update(Outbound=spare,Aliases=[old_node])
            retained,_=socks("fixed.invalid",port=entry_port)
            with retained:
                old_exit=marker(retained)
                submit(swapped)
                assert marker(retained)==old_exit
            assert Path("core.pid").read_text()==before_pid
            added=copy.deepcopy(swapped)
            new_line=copy.deepcopy(added["Exits"][0])
            new_line.update(Id="new",Name="new",Aliases=["volatile.invalid"])
            new_line["Outbound"]["settings"]["address"]="new.lab.invalid"
            added["Exits"].append(new_line)
            assert resolve("volatile") in ("198.51.100.1","198.51.100.2")
            with contextlib.ExitStack() as existing_flows:
                held=existing_flows.enter_context(socks("fixed.invalid",port=entry_port)[0])
                prior_tcp=marker(held)
                datagram=udp_flow(existing_flows,entry=entry_port)
                prior_udp=datagram()
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    publication=pool.submit(submit, added)
                    while not publication.done():
                        assert marker(held)==prior_tcp and datagram()==prior_udp
                        time.sleep(.3)
                    publication.result()
                try: tcp_continued=marker(held)==prior_tcp
                except (OSError,EOFError): tcp_continued=False
                try: udp_continued=datagram()==prior_udp
                except (OSError,EOFError): udp_continued=False
            assert Path("core.pid").read_text()==before_pid
            assert resolve("volatile")=="198.51.100.5" and "volatile.invalid" in backup.queries
            assert "new.lab.invalid" in backup.queries
            wait(lambda:status().get("new",{}).get("Healthy"))
            alive["A"]=alive["B"]=False
            wait(lambda:all(not row["Healthy"] for row in status().values() if not row["Direct"]))
            assert resolve("foreign-failed") is None
            assert "foreign-failed.invalid" not in backup.queries
            assert status()["D"]["Healthy"] and resolve("direct")=="127.0.0.1"
            alive["A"]=alive["B"]=True
            wait(lambda:all(row["Healthy"] for row in status().values()))
            submit(managed)
            assert Path("core.pid").read_text()==before_pid
            assert resolve("volatile") in ("198.51.100.1","198.51.100.2")
            assert not leaks, "managed traffic used system DNS"
            hosts.write_text(saved_hosts+"127.0.0.1 check.lab.invalid\n")
            print("split DoH: host DNS unavailable, direct and proxy answers, bootstrap, preflight, hot swap, new domain, outage and recovery passed",flush=True)
            assert resolve("new-profile") in ("198.51.100.1","198.51.100.2")
            assert load("xray.json")["dns"]["servers"][0]==managed["ManagedDohResolvers"][0]
            good=load("committed.json")
            bad=copy.deepcopy(managed)
            bad["ManagedDohResolvers"]=["https://192.0.2.77:443/dns-query"]
            submit(bad,ok=False,restart=True)
            assert load("committed.json")==good and resolve("rolled-back") in ("198.51.100.1","198.51.100.2")
            submit(previous,restart=True)
            assert "dns" not in load("xray.json")
            # Simulate an expired publication after the candidate reached disk.
            # The supervised process is independent of the publish request.
            original=Path("xray.json").read_text()
            timer=load("watchdog.json")
            dump("transaction.json",dict(PreviousXray=original,PreviousState=load("committed.json"),
                                         XrayService="xray-lab",RestartId=timer[-1]))
            dump("xray.json",dict(log=dict(loglevel="error")))
            subprocess.run(timer,env=env,check=True,timeout=25)
            assert Path("xray.json").read_text()==original and not Path("transaction.json").exists()
            assert load(Path("receipts")/(timer[-1]+".json"))["Success"] is False
            print("managed DoH: first setup, verified restart, bad resolver rollback, restore, watchdog: passed",flush=True)
            print("existing public-entry flows across new bootstrap-domain registration: TCP=%s UDP=%s" %
                  (tcp_continued,udp_continued),flush=True)
            assert tcp_continued and udp_continued, "new domain publication interrupted existing entry sessions"
        except Exception:
            # Suppress process logs: candidate transports may contain authentication fields.
            raise
if __name__=="__main__":run(sys.argv[1],sys.argv[2])
