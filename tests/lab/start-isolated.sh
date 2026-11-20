#!/usr/bin/env bash
# Run under unshare --mount --net --propagation private. All services are loopback-only.
set -eu
set -E
bridge=$1
trap 'echo "$LINENO" > "$bridge/fixture-failure-line"' ERR
kernel=$2
packages=$3
fixture=$4
test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)"
test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)"
mount -t tmpfs tmpfs /run
mkdir -p /run/sshd /run/panel-lab
cd /run/panel-lab
base=$PWD
umask 077
ip link set lo up
ip address add 192.0.2.53/32 dev lo
if [ "$packages" != "/" ]; then
    mount --bind "$packages/usr/lib/openssh" /usr/lib/openssh
    export LD_LIBRARY_PATH="$packages/usr/lib/x86_64-linux-gnu"
fi
if ! getent passwd sshd >/dev/null; then
    cp /etc/passwd passwd
    printf 'sshd:x:59005:65534:sshd:/nonexistent:/usr/sbin/nologin\n' >> passwd
    mount --bind "$base/passwd" /etc/passwd
fi
# Both test endpoints derive an ephemeral password in memory from the random,
# owner-only fixture key. Only its salted password hash enters the private shadow.
verifier=$(sha256sum "$bridge/client" | cut -d ' ' -f 1 | openssl passwd -6 -stdin)
awk -F: -v OFS=: -v verifier="$verifier" '$1=="root" {$2=verifier} {print}' /etc/shadow > shadow
mount --bind "$base/shadow" /etc/shadow
printf '127.0.0.1 localhost node.test spare.test check.test\n' > hosts
mount --bind "$base/hosts" /etc/hosts
cp "$kernel" xray
ssh-keygen -q -t ed25519 -N '' -f host
cp "$bridge/client.pub" authorized_keys
ssh-keygen -q -t ed25519 -N '' -f agent_key
cat agent_key.pub >> authorized_keys
cp agent_key.pub "$bridge/agent-public"
ssh-agent -D -a "$base/agent.sock" >/dev/null 2>&1 & agent=$!
for i in {1..60}; do [ -S "$base/agent.sock" ] && break; sleep .05; done
SSH_AUTH_SOCK="$base/agent.sock" ssh-add agent_key >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=check.test -addext 'subjectAltName=DNS:check.test,DNS:node.test,IP:192.0.2.53' -keyout tls.key -out tls.pem 2>/dev/null
python3 "$fixture/backend.py" "$base" >backend.log 2>&1 & backend=$!
daemon=''
alternate=''
relay_pid=''
api_pid=''
target_pid=''
migration_src=''
cgroup=''
stop() {
    if [ -n "$cgroup" ] && [ -e "$cgroup/cgroup.kill" ]; then echo 1 > "$cgroup/cgroup.kill" 2>/dev/null || true; fi
    [ -z "$target_pid" ] || { kill -KILL "$target_pid" 2>/dev/null || true; wait "$target_pid" 2>/dev/null || true; }
    [ -z "$migration_src" ] || { kill "$migration_src" 2>/dev/null || true; wait "$migration_src" 2>/dev/null || true; }
    if [ -n "$cgroup" ]; then find "$cgroup" -depth -type d -exec rmdir {} \; 2>/dev/null || true; fi
    for pid in "$relay_pid" "$api_pid" "$backend" "$daemon" "$alternate" "$agent"; do
        [ -z "$pid" ] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
}
trap stop EXIT
for i in {1..120}; do [ -f live.pid ] && break; sleep .1; done
test -f live.pid
if [ "${5:--}" != "-" ]; then
    mount -t tmpfs tmpfs /var/lib
    mount -t tmpfs tmpfs /usr/local/bin
    install -m 755 "$5" /usr/local/bin/vpspanel-relay
    work=/var/lib/vpspanel
    mkdir -m 700 "$work"
    cat > "$work/xray.json" <<'JSON'
{"api":{"listen":"127.0.0.1:25333","tag":"api","services":["HandlerService","RoutingService"]},"inbounds":[],"outbounds":[{"tag":"closed","protocol":"blackhole"}],"routing":{"rules":[{"type":"field","network":"tcp,udp","outboundTag":"closed"}]}}
JSON
    cat > "$work/relay.json" <<JSON
{"Xray":"$base/xray","ApiPort":25333,"ListenPort":25334,"CheckUrl":"https://check.test:24443/ok","ProbeSeconds":1}
JSON
    ./xray run -c "$work/xray.json" >relay-core.log 2>&1 & api_pid=$!
    for i in {1..60}; do nc -z 127.0.0.1 25333 && break; sleep .1; done
    SSL_CERT_FILE="$base/tls.pem" /usr/local/bin/vpspanel-relay serve "$work" >relay.log 2>&1 & relay_pid=$!
    for i in {1..100}; do [ -f "$work/status.json" ] && break; sleep .1; done
    test -f "$work/status.json"
    echo '{"Exits":[],"Policy":{"Groups":[],"Rules":[]},"Total":{"Enabled":false}}' > bootstrap.json
    /usr/local/bin/vpspanel-relay submit "$work" bootstrap.json >/dev/null
    for i in {1..100}; do [ -f "$work/committed.json" ] && break; sleep .1; done
    test -f "$work/committed.json"
fi
# Only service discovery is substituted. /proc, binaries, files, SSH, SFTP and both proxies are real.
printf '#!/bin/sh\n[ "$1 $2 $3 $4" = "show --property=MainPID --value phase2-lab" ] && cat %s/live.pid\n' "$base" > systemctl
chmod +x systemctl
if [ "${6:--}" = migration ]; then
    python3 - <<'PY'
import json
c=json.load(open("live config.json"))
i=c["inbounds"][0]
i["tag"]="fixture-user";i["port"]=28445
c["inbounds"].append(dict(tag="fixture-system",listen="127.0.0.1",port=28446,protocol="dokodemo-door",settings=dict(address="127.0.0.1",port=24443,network="tcp")))
c["routing"]["rules"].insert(0,dict(type="field",inboundTag=["fixture-system","fixture-resolver"],outboundTag="lab-direct"))
json.dump(c,open("migration-source.json","w"))
PY
    ./xray run -c migration-source.json >migration-src.log 2>&1 & migration_src=$!
    printf '#!/bin/sh\ncase "$4" in phase2-lab) cat %s/live.pid;; migration-source) echo %s;; *) exit 1;; esac\n' "$base" "$migration_src" > systemctl
    mkdir -p "$base/target-root" "$base/upper" "$base/overlay-work"
    cgroup=/sys/fs/cgroup/panel-migration-$$;mkdir "$cgroup"
    (echo "$BASHPID" > "$cgroup/cgroup.procs";exec unshare --pid --fork --kill-child=KILL --mount --uts --cgroup bash "$fixture/migration-target.sh" "$base" "$packages") > "$bridge/target-diagnostic.log" 2>&1 & target_pid=$!
    for i in {1..180}; do nc -z 127.0.0.1 26444 && break; kill -0 "$target_pid" || exit 2;sleep .1;done
    nc -z 127.0.0.1 26444
    echo "$migration_src" > "$bridge/source-pid"
fi
mount --bind "$base/systemctl" /usr/bin/systemctl
cat > sshd_config <<EOF
ListenAddress 127.0.0.1
Port 26442
HostKey $base/host
AuthorizedKeysFile $base/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication yes
PermitRootLogin yes
AllowTcpForwarding no
Subsystem sftp internal-sftp
PidFile $base/sshd.pid
SetEnv CURL_CA_BUNDLE=$base/tls.pem
EOF
"$packages/usr/sbin/sshd" -D -e -f "$base/sshd_config" >sshd.log 2>&1 & daemon=$!
ssh-keygen -q -t ed25519 -N '' -f alternate_host
sed -e 's/26442/26443/' -e 's|/host$|/alternate_host|' -e 's|/sshd.pid$|/alternate.pid|' sshd_config > alternate_config
"$packages/usr/sbin/sshd" -D -e -f "$base/alternate_config" >alternate.log 2>&1 & alternate=$!
sleep .3
kill -0 "$daemon"
kill -0 "$alternate"
printf 'phase2-lab %s\n' "$(cut -d ' ' -f 1,2 host.pub)" > "$bridge/known_hosts"
if [ -f "$base/target-public" ]; then printf 'phase4-target %s\n' "$(cut -d ' ' -f 1,2 "$base/target-public")" >> "$bridge/known_hosts";fi
echo "$$" > "$bridge/ns.pid"
while [ ! -f "$bridge/stop" ]; do sleep .3; done
