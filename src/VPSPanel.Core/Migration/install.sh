#!/bin/sh
# Received over verified SSH. Run as an independent systemd transaction.
set -eu
umask 077
stage=$1
case "$stage" in /var/tmp/vpspanel-restore.*) ;; *) exit 2;; esac
base=/var/lib/vpspanel-releases
live=/var/lib/vpspanel
units=/etc/systemd/system
x=vpspanel-restored-xray.service
r=vpspanel-restored-relay.service
id=$(basename "$stage")
candidate=$base/$id
previous=''
switched=0
phase=prepare
own_candidate=0
made_x=0
made_r=0
old_x=0
old_r=0
enabled_x=0
enabled_r=0
report() { printf '%s\n' "$1" > "$stage/result.tmp"; mv -f "$stage/result.tmp" "$stage/result"; }
finish() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$rc" -ne 0 ]; then
        if [ "$switched" = 1 ]; then
            systemctl stop "$r" "$x" >/dev/null 2>&1 || :
            if [ -n "$previous" ]; then
                ln -s "$previous" "$candidate/revert"
                mv -Tf "$candidate/revert" "$live"
            else
                unlink "$live"
            fi
            [ "$enabled_x" = 1 ] || systemctl disable "$x" >/dev/null 2>&1 || :
            [ "$enabled_r" = 1 ] || systemctl disable "$r" >/dev/null 2>&1 || :
        fi
        [ "$made_x" = 0 ] || rm -f -- "$units/$x"
        [ "$made_r" = 0 ] || rm -f -- "$units/$r"
        systemctl daemon-reload
        if [ "$old_x" = 1 ]; then systemctl start "$x" || { report rollback-error; exit 1; }; fi
        if [ "$old_r" = 1 ]; then
            systemctl start "$r" || { report rollback-error; exit 1; }
            # Type=exec only confirms execve. Wait until the restored data plane accepts a request.
            if [ "$switched" = 1 ] && [ "$old_x" = 1 ]; then
                timeout 115 "$live/relay" restore-check "$live" >/dev/null 2>&1 || { report rollback-error; exit 1; }
            fi
        fi
        rm -f -- "$base/pending"
        report "rejected-$phase"
    fi
    rm -rf -- "$stage/release"
    rm -f -- "$stage/backup" "$stage/relay"
    if [ "$rc" -ne 0 ] && [ "$own_candidate" = 1 ] && [ "$(readlink -f "$live" || :)" != "$candidate" ]; then rm -rf -- "$candidate"; fi
    exit "$rc"
}
abandon() { rm -rf -- "$stage/release";rm -f -- "$stage/relay" "$stage/backup";report "$1";exit 1; }
if mkdir -m 700 "$base" 2>/dev/null; then printf '1\n' > "$base/.vpspanel-release-store";fi
[ ! -L "$base" ] && [ "$(stat -c '%u:%a' "$base")" = 0:700 ] && [ -f "$base/.vpspanel-release-store" ] || abandon rejected-prepare
exec 9>"$base/deploy.lock"
flock -n 9 || abandon busy
trap finish EXIT
trap 'exit 1' HUP INT TERM
# Recover a lost deploy worker before the next boot of Xray. The lock is held during a live transaction.
cat > "$stage/recover-link" <<'GUARD'
#!/bin/sh
set -eu
base=/var/lib/vpspanel-releases
test -f "$base/pending" || exit 0
previous=$(cat "$base/pending")
if [ -n "$previous" ]; then
    [ "$(dirname "$previous")" = "$base" ] && [ -f "$previous/verified" ] || exit 1
    ln -s "$previous" "$base/recover.$$"
    mv -Tf "$base/recover.$$" /var/lib/vpspanel
else
    if [ -L /var/lib/vpspanel ];then unlink /var/lib/vpspanel;fi
fi
rm -f -- "$base/pending"
sync -f "$base"
GUARD
install -m 700 "$stage/recover-link" "$base/recover-link.new"
mv -Tf "$base/recover-link.new" "$base/recover-link"
"$base/recover-link"
# Never claim an unmanaged installation or overwrite a foreign unit.
if [ -e "$live" ] || [ -L "$live" ]; then
    [ -L "$live" ]; previous=$(readlink -f "$live")
    [ "$(dirname "$previous")" = "$base" ] && [ -f "$previous/verified" ] || exit 1
fi
cat > "$stage/$x" <<'UNIT'
[Unit]
Description=VPSPanel restored Xray
After=network-online.target
[Service]
Type=exec
WorkingDirectory=/var/lib/vpspanel
Environment=XRAY_LOCATION_ASSET=/var/lib/vpspanel
ExecStartPre=/usr/bin/flock -n -E 0 /var/lib/vpspanel-releases/deploy.lock /var/lib/vpspanel-releases/recover-link
ExecStart=/var/lib/vpspanel/xray run -c /var/lib/vpspanel/xray.json
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat > "$stage/$r" <<'UNIT'
[Unit]
Description=VPSPanel restored Relay
Wants=vpspanel-restored-xray.service
After=vpspanel-restored-xray.service
[Service]
Type=exec
WorkingDirectory=/var/lib/vpspanel
ExecStart=/var/lib/vpspanel/relay serve /var/lib/vpspanel
Restart=on-failure
RestartSec=1
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
for unit in "$x" "$r"; do
    fragment=$(systemctl show "$unit" -p FragmentPath --value)
    drops=$(systemctl show "$unit" -p DropInPaths --value)
    [ -z "$drops" ]
    if [ -e "$units/$unit" ] || [ -n "$fragment" ]; then
        [ -n "$previous" ] && [ "$fragment" = "$units/$unit" ] && cmp -s "$stage/$unit" "$units/$unit" || exit 1
    fi
done
# Reusing a listener is only safe when the previous managed service owns it.
python3 - "$stage/release" "$x" "$r" <<'PY'
import json, pathlib, re, subprocess, sys
release = pathlib.Path(sys.argv[1])
owned = set()
for unit in sys.argv[2:]:
    pid = subprocess.run(["systemctl","show",unit,"--property=MainPID","--value"],capture_output=True,text=True).stdout.strip()
    if pid.isdigit() and pid != "0":
        owned.add(pid)
cfg = json.loads((release/"xray.json").read_text())
options = json.loads((release/"relay.json").read_text())
ports = {int(options["ApiPort"]), int(options["ListenPort"])}
for inbound in cfg["inbounds"]:
    port = inbound.get("port")
    if port is None and str(inbound.get("listen","")).startswith("/"):
        raise SystemExit(1)
    ports.add(int(port))
for line in subprocess.check_output(["ss","-Hlnptu"],text=True).splitlines():
    cols = line.split()
    port = cols[4].rsplit(":",1)[-1]
    if port.isdigit() and int(port) in ports:
        pids = set(re.findall(r"pid=(\d+)",line))
        if not pids or not pids.issubset(owned):
            raise SystemExit(1)
PY
phase=static
# Candidate files were fully authenticated, unpacked and statically tested.
[ ! -e "$candidate" ] && [ ! -L "$candidate" ] || abandon rejected-prepare
own_candidate=1
mv -T "$stage/release" "$candidate"
(cd "$candidate"; XRAY_LOCATION_ASSET="$candidate" ./xray run -test -c xray.json >/dev/null 2>&1)
if [ ! -e "$units/$x" ]; then install -m 644 "$stage/$x" "$units/$x"; made_x=1; fi
if [ ! -e "$units/$r" ]; then install -m 644 "$stage/$r" "$units/$r"; made_r=1; fi
systemctl daemon-reload
systemctl is-active --quiet "$x" && old_x=1
systemctl is-active --quiet "$r" && old_r=1
systemctl is-enabled --quiet "$x" && enabled_x=1
systemctl is-enabled --quiet "$r" && enabled_r=1
ln -s "$candidate" "$candidate/next"
phase=activation
printf '%s\n' "$previous" > "$base/pending.new"; mv -Tf "$base/pending.new" "$base/pending"; sync -f "$base"
# If interrupted before the link swap, the previous link remains valid.
[ "$old_r" = 0 ] || systemctl stop "$r"
[ "$old_x" = 0 ] || systemctl stop "$x"
mv -Tf "$candidate/next" "$live"
switched=1
systemctl start "$x" "$r"
phase=exits
# status.json is newly generated in this release; wait for two good health samples.
ok=0
for i in $(seq 1 50); do
    if python3 - "$live" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
try:
    plan=json.loads((p/'plan.json').read_text())
    good={l['Id'] for l in json.loads((p/'status.json').read_text())['Links'] if l['Healthy']}
    required={e['Id'] for e in plan['Exits'] if e['Enabled']}
    assert required and required==good
except Exception:sys.exit(1)
PY
    then ok=1;break;fi
    sleep 1
done
[ "$ok" = 1 ]
phase=ingress
timeout 115 "$live/relay" restore-check "$live"
systemctl enable "$x" "$r" >/dev/null
touch "$candidate/verified"
sync -f "$candidate"
rm -f -- "$base/pending"; sync -f "$base"
report verified
