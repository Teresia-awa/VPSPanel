# Sent over the authenticated SSH session. The plan (including credentials) arrives on stdin.
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

work = Path("/var/lib/vpspanel")


def prop(unit, key):
    return subprocess.check_output(["systemctl", "show", "--property=" + key, "--value", unit],
                                   stderr=subprocess.DEVNULL, text=True, timeout=8).strip()


def service(unit):
    pid = int(prop(unit, "MainPID"))
    if pid <= 1 or prop(unit, "ActiveState") != "active":
        raise ValueError("inactive")
    proc = Path("/proc", str(pid))
    args = (proc / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
    return proc, args


def bound_credential(unit, candidate):
    if "config.json:" + candidate in prop(unit, "LoadCredential").split():
        return True
    # Some systemd versions omit this array from "show". The takeover installs
    # one drop-in resetting the array and binding exactly this credential.
    files = prop(unit, "DropInPaths").split()
    if len(files) != 1 or prop(unit, "NeedDaemonReload") != "no":
        return False
    lines = [s.strip() for s in Path(files[0]).read_text().splitlines()
             if s.strip() and not s.lstrip().startswith(("#", ";"))]
    return lines == ["[Service]", "LoadCredential=", "LoadCredential=config.json:" + candidate]


def binding(unit):
    restored = unit == "vpspanel-restored-xray"
    relay, args = service("vpspanel-restored-relay" if restored else "vpspanel-relay")
    if args[1:] != ["serve", str(work)] or not (relay / "exe").samefile(work / "relay"):
        raise ValueError("relay identity")
    proc, args = service(unit)
    settings = json.loads((work / "relay.json").read_bytes())
    if not (proc / "exe").samefile(settings["Xray"]):
        raise ValueError("kernel identity")
    configs = [args[i+1] for i in range(len(args)-1) if args[i] in ("-c", "-config")]
    source = work / "source.json" if restored else Path("/etc/xray-relay/config.json")
    candidate = str(work / "xray.json")
    credential = "/run/credentials/" + unit + ".service/config.json"
    if configs != [candidate] and not (configs == [credential] and bound_credential(unit, candidate)):
        raise ValueError("config binding")
    cfg = json.loads(Path(candidate).read_bytes())
    if (cfg.get("api", {}).get("tag") != "vpspanel-control" or
        cfg["api"]["listen"] != "127.0.0.1:" + str(settings["ApiPort"]) or not source.is_file()):
        raise ValueError("config identity")
    if time.time() - (work / "status.json").stat().st_mtime > 30:
        raise ValueError("stale status")
    return str(source), settings["CheckUrl"]


def handle():
    data = json.load(sys.stdin)
    op, unit = data["Op"], data["Service"].removesuffix(".service")
    source, url = binding(unit)
    state = work / "committed.json"
    request = work / "request.json"
    journal = work / "transaction.json"

    def current():
        raw = state.read_bytes()
        status = json.loads((work / "status.json").read_bytes())
        return dict(Revision=hashlib.sha256(raw).hexdigest(), Plan=json.loads(raw)["Plan"],
                    Source=source, CheckUrl=url,
                    SupportsDefaultRoute=status.get("SupportsDefaultRoute") is True,
                    SupportsExitFailover=status.get("SupportsExitFailover") is True)

    if op == "inspect":
        if request.exists() or journal.exists():
            return dict(Status="busy")
        return dict(Status="ok", Current=current())
    rid = data["Id"]
    if not re.fullmatch("[0-9a-f]{32}", rid):
        raise ValueError("id")
    receipt = work / "receipts" / (rid + ".json")
    if op == "result":
        if receipt.exists():
            result = json.loads(receipt.read_bytes())
            if result["Id"] != rid:
                raise ValueError("receipt")
            return dict(Status="applied" if result["Success"] else "rejected", Current=current())
        if request.exists() and json.loads(request.read_bytes())["Id"] == rid:
            return dict(Status="pending")
        # A receipt can land between checking the receipt and checking the request.
        return dict(Status="pending" if receipt.exists() else "unknown")
    if op != "submit":
        raise ValueError("op")

    os.umask(0o077)
    with (work / "publication.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if receipt.exists():
            return dict(Status="submitted")
        if request.exists() or journal.exists():
            return dict(Status="busy")
        # Existing Relay protocol. Exclusive publication also protects against older CLI writers.
        with tempfile.NamedTemporaryFile(dir=work, delete=False) as f:
            path = Path(f.name)
        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(dict(Id=rid, Plan=data["Plan"]), f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if current()["Revision"] != data["Revision"]:
                return dict(Status="stale")
            try:
                os.link(path, request)
            except FileExistsError:
                return dict(Status="busy")
            fd = os.open(work, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            path.unlink(missing_ok=True)
        return dict(Status="submitted")


try:
    print(json.dumps(handle(), ensure_ascii=True))
except Exception as error:
    safe = ("inactive", "relay identity", "kernel identity", "config binding", "config identity", "stale status")
    print(json.dumps(dict(Status="unavailable", Reason=str(error) if isinstance(error, ValueError) and str(error) in safe else "read")))
