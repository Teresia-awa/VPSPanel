#!/bin/bash
# PID 1 of a disposable system whose only network is the existing lab loopback.
set -eu
base=$1; packages=$2; root=$base/target-root
mount --make-rprivate /
mount -t tmpfs -o mode=755 tmpfs "$root"
mkdir -p "$root"/{usr,etc/systemd/system,run,tmp,var/tmp,var/lib,proc,sys,dev,root,home,opt/ssh}
chmod 1777 "$root/tmp" "$root/var/tmp"
mount --bind /usr "$root/usr"
mount -o remount,bind,ro "$root/usr"
for d in bin sbin lib lib64; do [ ! -e "/$d" ] || ln -s "usr/$d" "$root/$d"; done
mount -t proc proc "$root/proc"
mount -t sysfs sysfs "$root/sys"
mount -t cgroup2 none "$root/sys/fs/cgroup"
mount -t tmpfs -o mode=755 tmpfs "$root/dev"
for d in null zero random urandom tty console full; do
    [ -e "/dev/$d" ] || continue
    touch "$root/dev/$d"; mount --bind "/dev/$d" "$root/dev/$d"
done
mkdir -p "$root/dev/pts" "$root/dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666 devpts "$root/dev/pts"
ln -s pts/ptmx "$root/dev/ptmx"
for d in fd stdin stdout stderr; do ln -s "$(readlink /dev/$d)" "$root/dev/$d"; done
mount -t tmpfs -o mode=755 tmpfs "$root/run"
# systemd must retain /run across initialization in a container.
mkdir -p "$root/run/systemd" "$root/run/sshd" "$root/etc/ssh" "$root/etc/ssl/certs"
echo panel-lab > "$root/run/systemd/container"
printf 'root:x:0:0:root:/root:/bin/bash\nsshd:x:59005:65534:sshd:/nonexistent:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n' > "$root/etc/passwd"
printf 'root:x:0:\nnogroup:x:65534:\ntty:x:5:\n' > "$root/etc/group"
awk -F: '$1=="root"' /etc/shadow > "$root/etc/shadow"
chmod 600 "$root/etc/shadow"
cp "$base/hosts" "$root/etc/hosts"; cp "$base/tls.pem" "$root/etc/ssl/certs/lab.pem"
cp /etc/nsswitch.conf "$root/etc/";cp -L /etc/os-release "$root/etc/os-release"
ln -s /proc/self/mounts "$root/etc/mtab"; cat /proc/sys/kernel/random/uuid | tr -d '-' > "$root/etc/machine-id"
echo migration-fixture > "$root/etc/hostname"
cp "$base/authorized_keys" "$root/etc/ssh/authorized_keys"
ssh-keygen -q -t ed25519 -N '' -f "$root/etc/ssh/host"
cp "$root/etc/ssh/host.pub" "$base/target-public"
mount --bind "$packages/usr" "$root/opt/ssh"
cat > "$root/etc/ssh/sshd_config" <<'CONF'
ListenAddress 127.0.0.1
Port 26444
HostKey /etc/ssh/host
AuthorizedKeysFile /etc/ssh/authorized_keys
StrictModes yes
PermitRootLogin yes
PasswordAuthentication yes
UsePAM no
Subsystem sftp internal-sftp
SetEnv CURL_CA_BUNDLE=/etc/ssl/certs/lab.pem SSL_CERT_FILE=/etc/ssl/certs/lab.pem
CONF
# Keep the server's self-reexec and distro-specific ssh helpers available at their compiled paths.
if [ "$packages" != / ]; then
    # Overlayfs exposes the upper directory's mode as /usr. The fixture's
    # private staging umask must not prevent non-root services from running.
    chmod 0755 "$base/upper"
    mount -t overlay overlay -o "lowerdir=$packages/usr:/usr,upperdir=$base/upper,workdir=$base/overlay-work" "$root/usr"
fi
cat > "$root/etc/systemd/system/fixture-ssh.service" <<'UNIT'
[Service]
Type=exec
Environment=LD_LIBRARY_PATH=/opt/ssh/lib/x86_64-linux-gnu
RuntimeDirectory=sshd
ExecStart=/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
UNIT
cat > "$root/etc/systemd/system/panel-lab.target" <<'UNIT'
[Unit]
Description=Isolated migration target
Requires=fixture-ssh.service
After=fixture-ssh.service
UNIT
mkdir -p "$root/etc/systemd/system.conf.d"
printf '[Manager]\nDefaultEnvironment=SSL_CERT_FILE=/etc/ssl/certs/lab.pem\n' > "$root/etc/systemd/system.conf.d/lab.conf"
export container=panel-lab
exec chroot "$root" /lib/systemd/systemd --system --unit=panel-lab.target --log-target=console --show-status=false
