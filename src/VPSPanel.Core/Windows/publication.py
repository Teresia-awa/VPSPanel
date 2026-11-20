# Sent over the authenticated SSH session. The plan (including credentials) arrives on stdin.
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

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
    # Older systemd releases omit LoadCredential from show. Replay the effective
    # unit fragments in order, including resets and unrelated environment drop-ins.
    if prop(unit, "NeedDaemonReload") != "no":
        return False
    files = [prop(unit, "FragmentPath"), *prop(unit, "DropInPaths").split()]
    credentials = []
    for path in files:
        section = ""
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line
            elif section == "[Service]" and line.startswith("LoadCredential="):
                value = line.partition("=")[2].strip()
                if not value:
                    credentials.clear()
                elif value.partition(":")[0] == "config.json":
                    credentials.append(value)
    return credentials == ["config.json:" + candidate]


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
    try:
        active = cfg if configs == [candidate] else json.loads(Path(credential).read_bytes())
    except (OSError, ValueError):
        active = {}
    dns = active.get("dns") or {}
    mode = "configured" if dns else "none"
    return str(source), settings, mode, cfg


def handle():
    data = json.load(sys.stdin)
    op, unit = data["Op"], data["Service"].removesuffix(".service")
    source, settings, dns_mode, config = binding(unit)
    persistent_dns, persistent_geo = config.get("dns"), config.get("geodata")
    state = work / "committed.json"
    request = work / "request.json"
    journal = work / "transaction.json"

    def current():
        raw = state.read_bytes()
        status = json.loads((work / "status.json").read_bytes())
        committed = json.loads(raw)
        plan = committed["Plan"]
        original = committed.get("PreviousDns") if plan.get("ManagedDohResolvers") is not None else persistent_dns
        uses_asset = any(isinstance(s, dict) and "ext:vpspanel-bootstrap.dat:bindings" in s.get("domains", [])
                         for s in (persistent_dns or {}).get("servers", []))
        original_geo = committed.get("PreviousGeodata") if uses_asset else persistent_geo
        result = dict(Revision=hashlib.sha256(raw).hexdigest(), Plan=plan,
                    Source=source, CheckUrl=settings["CheckUrl"],
                    SupportsDefaultRoute=status.get("SupportsDefaultRoute") is True,
                    SupportsExitFailover=status.get("SupportsExitFailover") is True,
                    SupportsEncryptedDnsRouting=status.get("SupportsEncryptedDnsRouting") is True,
                    SupportsDnsFailurePolicy=status.get("SupportsDnsFailurePolicy") is True,
                    SupportsSplitDoh=status.get("SupportsSplitDoh") is True,
                    SupportsManagedDoh=status.get("SupportsManagedDoh") is True, ServerDnsMode=dns_mode,
                    UsesBootstrapAsset=uses_asset,
                    OriginalGeodata=original_geo if data.get("ExportLayout") is True else None,
                    OriginalDns=original if data.get("ExportLayout") is True else None)
        if data.get("ExportLayout") is True:
            # A systemd credential can still contain the boot-time copy after an API hot update.
            # Check the running handlers against the bound, durable configuration.
            def live_rows(command, field):
                result = subprocess.check_output([settings["Xray"], "api", command,
                                                  "--server=127.0.0.1:" + str(settings["ApiPort"])],
                                                 stderr=subprocess.DEVNULL, timeout=12)
                return json.loads(result).get(field, [])

            running = {i.get("tag", "") for i in live_rows("lsi", "inbounds")}
            stored = {i.get("tag", "") for i in config["inbounds"]}
            extra = running - stored - {"vpspanel-control"}
            if stored - running or any(not re.fullmatch(r"vp3-[0-9a-f]{32}", tag) for tag in extra):
                raise ValueError("layout changed")
            # Draining generations may still own an extra routing rule until their sessions end.
            active_rules = [(r.get("ruleTag"), r.get("tag")) for r in live_rows("lsrules", "rules")
                            if r.get("ruleTag") not in extra]
            # The Xray API reports no outbound tag for a balancer rule.
            expected_rules = [(r.get("ruleTag") or None, r.get("outboundTag") or None)
                              for r in config["routing"]["rules"]]
            if active_rules != expected_rules:
                raise ValueError("layout changed")
            if (request.exists() or journal.exists() or state.read_bytes() != raw or
                    json.loads((work / "xray.json").read_bytes()) != config):
                raise ValueError("layout changed")
            result.update(ExportLayout=config, LaneTags=[lane["Tag"] for lane in committed["Lanes"]],
                          RelayPort=settings["ListenPort"])
        return result

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
        previous = current()
        if previous["Revision"] != data["Revision"]:
            return dict(Status="stale")
        plan = data["Plan"]
        restart = data.get("RestartXray") is True
        if (restart or plan.get("ManagedDohResolvers") is not None) and not previous["SupportsSplitDoh"]:
            return dict(Status="needs-restart")
        # Existing Relay protocol. Exclusive publication also protects against older CLI writers.
        with tempfile.NamedTemporaryFile(dir=work, delete=False) as f:
            path = Path(f.name)
        try:
            with path.open("w", encoding="utf-8") as f:
                submission = dict(Id=rid, Plan=plan)
                if restart:
                    submission["XrayService"] = unit
                json.dump(submission, f, ensure_ascii=False)
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
    safe = ("inactive", "relay identity", "kernel identity", "config binding", "config identity", "stale status", "layout changed")
    print(json.dumps(dict(Status="unavailable", Reason=str(error) if isinstance(error, ValueError) and str(error) in safe else "read")))
