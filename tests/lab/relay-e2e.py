"""Two independent HY2 peers and an actual pinned Xray, inside a loopback-only namespace."""
import concurrent.futures, contextlib, copy, json, os, secrets, shutil, socket, socketserver
import struct, subprocess, sys, tempfile, threading, time
from pathlib import Path

PEERS = {"A": 23101, "B": 23101}
BACKENDS = {"A": 23201, "B": 23202, "D": 23203}
delay = {name: .015 for name in BACKENDS}
alive = dict.fromkeys(BACKENDS, True)
address = "127.0.0.1"
api, relay_port, entry_port = 23301, 23302, 23303
unlimited = dict(Enabled=False, Upload=0, Download=0)

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
    subprocess.run(["ip","link","set","lo","up"],check=True)
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
        def start(args):
            p=subprocess.Popen(args,stdout=log,stderr=log);stack.callback(stop,p);return p
        def start_xray(file):return start([xray,"run","-c",file])
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout","tls.key","-out","tls.pem","-days","1","-subj","/CN=lab.invalid","-addext","subjectAltName=DNS:lab.invalid"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cert=str(work/"tls.pem");auth=secrets.token_hex(18)
        def freedom(tag,redirect=None):
            opts=dict(finalRules=[dict(action="allow",ip=["127.0.0.0/8"]),dict(action="block")])
            if redirect:opts["redirect"]=address+":"+str(redirect)
            return dict(tag=tag,protocol="freedom",settings=opts)
        def outgoing(name):
            return dict(protocol="hysteria",settings=dict(version=2,address=name.lower()+".lab.invalid",port=PEERS[name]),
                streamSettings=dict(network="hysteria",security="tls",tlsSettings=dict(serverName="lab.invalid",alpn=["h3"],certificates=[dict(usage="verify",certificateFile=cert)]),hysteriaSettings=dict(version=2,auth=auth)))
        for name,p in PEERS.items():
            ingress=dict(listen="127.0.0."+("2" if name=="A" else "3"),port=p,protocol="hysteria",settings=dict(version=2,users=[dict(auth=auth)]),streamSettings=dict(network="hysteria",security="tls",tlsSettings=dict(alpn=["h3"],certificates=[dict(certificateFile=cert,keyFile=str(work/"tls.key"))]),hysteriaSettings=dict(version=2)))
            file=name+".json";dump(file,dict(inbounds=[ingress],outbounds=[freedom("backend",BACKENDS[name])]))
            start_xray(file)
        base=dict(api=dict(tag="api",listen=address+":"+str(api),services=["HandlerService","RoutingService"]),
            inbounds=[dict(tag="entry",protocol="socks",listen=address,port=entry_port,settings=dict(udp=True))],
            outbounds=[dict(tag="closed",protocol="blackhole"),dict(tag="relay",protocol="socks",settings=dict(servers=[dict(address=address,port=relay_port)]))],
            routing=dict(rules=[dict(type="field",inboundTag=["entry"],outboundTag="relay")]))
        dump("xray.json",base)
        dump("relay.json",dict(Xray=xray,ApiPort=api,ListenPort=relay_port,CheckUrl="http://127.0.0.1:"+str(BACKENDS["D"])+"/ok",ProbeSeconds=1))
        def listening(port):
            with socket.create_connection((address,port),.15):return True
        def servers():
            x=start_xray("xray.json");wait(lambda:listening(api))
            r=start([binary,"serve",tmp]);wait(lambda:listening(relay_port))
            return x,r
        def submit(plan,ok=True,command="submit"):
            dump("input.json",plan)
            if command=="submit-existing":rid=subprocess.check_output([binary,command,tmp,"-"],input=json.dumps(plan),text=True).strip()
            else:rid=subprocess.check_output([binary,command,tmp,"input.json"],text=True).strip()
            def result():
                data=load("result.json")
                return data if data["Id"]==rid else None
            out=wait(result,30)
            assert out["Success"]==ok,out
            wait(lambda:not Path("request.json").exists())
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
            expect_failure("default.invalid");assert status()["D"]["Healthy"] and status()["D"]["Assigned"]==0
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
                hosts=["fixed.invalid","fixed.invalid" if mode=="exit" else "other.invalid"]
                with contextlib.ExitStack() as streams:
                    first=streams.enter_context(socks(hosts[0])[0])
                    cap=dict(Enabled=True,Upload=1,Download=2)
                    update=dict(Policy=policy,Total=cap if mode=="overall" else unlimited,Settings=[dict(Id="A",Enabled=True,Limit=cap if mode=="exit" else unlimited)])
                    submit(update,command="submit-policy");second=streams.enter_context(socks(hosts[1])[0]);pair=[first,second]
                    up=timed_pair(pair,b"U");down=timed_pair(pair,b"D")
                    assert 2.2<up<5 and 1<down<3,(mode,up,down)
                    update["Total"]=unlimited;update["Settings"][0]["Limit"]=unlimited;submit(update,command="submit-policy")
                    fast=timed_pair(pair,b"D");assert fast<.8,fast
                    print("%s shared: upload %.2fs, download %.2fs, disabled %.2fs"%(mode,up,down,fast),flush=True)
        except Exception:
            log.flush();log.seek(0)
            # Process output belongs solely to this disposable namespace; suppress configs/credentials.
            for line in log.readlines()[-100:]:
                if any(x in line for x in ("failed","error","Failed","Relay","校验","失败")):print(line.rstrip()[:400],file=sys.stderr)
            raise
if __name__=="__main__":run(sys.argv[1],sys.argv[2])
