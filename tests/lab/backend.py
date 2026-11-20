import json, os, secrets, ssl, subprocess, sys, threading, time, signal, uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
base = Path(sys.argv[1])
os.chdir(base)
class Reply(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/publication":
            self.send_response(503 if (base/"reject-publication").exists() else 204)
        else:
            self.send_response(204 if self.path == "/ok" else 404)
        self.end_headers()
    def log_message(self, *args): pass
srv = ThreadingHTTPServer(("127.0.0.1",24443),Reply)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.set_alpn_protocols(["http/1.1"])
ctx.load_cert_chain("tls.pem","tls.key")
srv.socket = ctx.wrap_socket(srv.socket,server_side=True)
threading.Thread(target=srv.serve_forever,daemon=True).start()
# The two paths are served with a private fixture CA and an IP subjectAltName.
import runpy
fixture = runpy.run_path(str(Path(__file__).resolve().with_name("relay-e2e.py")))
doh = fixture["Server"](("192.0.2.53",24453),fixture["DohHandler"])
doh.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
doh.tls.load_cert_chain("tls.pem","tls.key")
doh.tls.set_alpn_protocols(["h2"])
doh.records = {name:"127.0.0.1" for name in ("node.test","spare.test","check.test")}
doh.queries, doh.answer = [], "192.0.2.8"
threading.Thread(target=doh.serve_forever,daemon=True).start()
cert = str(base/"tls.pem")
auth = secrets.token_hex(16)
def raw(name, o):
    path = base/(name+".json")
    path.write_text(json.dumps(o))
    return subprocess.Popen(["./xray","run","-c",str(path)],stdout=sys.stderr,stderr=sys.stderr)
tls = dict(serverName="node.test",alpn=["h3"],certificates=[dict(usage="verify",certificateFile=cert)])
hy2 = dict(tag="lab-up",protocol="hysteria",settings=dict(version=2,address="node.test",port=23443),streamSettings=dict(network="hysteria",security="tls",tlsSettings=tls,hysteriaSettings=dict(version=2,auth=auth)))
ingress = dict(listen="127.0.0.1",port=23443,protocol="hysteria",settings=dict(version=2,users=[dict(auth=auth)]),streamSettings=dict(network="hysteria",security="tls",tlsSettings=dict(alpn=["h3"],certificates=[dict(certificateFile=cert,keyFile=str(base/"tls.key"))]),hysteriaSettings=dict(version=2)))
up = raw("upstream",dict(inbounds=[ingress],outbounds=[dict(protocol="freedom",settings=dict(finalRules=[dict(action="allow",ip=["127.0.0.1/32","192.0.2.53/32"],port="24443,24453"),dict(action="block")]))]))
keys = [line.split(":",1)[1].strip() for line in subprocess.check_output(["./xray","x25519"],text=True).splitlines()[:2]]
uid = str(uuid.uuid4())
sid = secrets.token_hex(4)
reality = dict(target="127.0.0.1:24443",serverNames=["node.test"],shortIds=[sid])
reality["privateKey"] = keys[0]
vless = dict(tag="lab-reality",protocol="vless",settings=dict(address="node.test",port=23445,id=uid,encryption="none"),
             streamSettings=dict(network="raw",security="reality",realitySettings=dict(serverName="node.test",fingerprint="chrome",publicKey=keys[1],shortId=sid)))
vless_in = dict(tag="test-in",listen="127.0.0.1",port=23445,protocol="vless",settings=dict(decryption="none",clients=[dict(id=uid)]),
                streamSettings=dict(network="raw",security="reality",realitySettings=reality))
direct = dict(tag="lab-direct",protocol="freedom",settings=dict(finalRules=[dict(action="allow",ip=["127.0.0.1/32","192.0.2.53/32"],port="24443,24453"),dict(action="block")]))
rules = [dict(type="field",domain=["domain:fixture.invalid"],outboundTag="lab-up"),
         dict(type="field",ip=["192.0.2.0/24"],outboundTag="lab-direct"),
         dict(type="field",domain=["domain:media.invalid"],outboundTag="lab-reality"),
         dict(type="field",network="tcp,udp",outboundTag="lab-direct")]
live = raw("live config",dict(inbounds=[vless_in],outbounds=[hy2,direct,vless],routing=dict(rules=rules)))
def done(*args):
    for p in (live,up): p.terminate()
    sys.exit(0)
signal.signal(signal.SIGTERM,done)
time.sleep(.5)
if any(p.poll() is not None for p in (up,live)): done()
Path("live.pid").write_text(str(live.pid))
signal.pause()
