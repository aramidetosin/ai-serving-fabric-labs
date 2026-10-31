#!/usr/bin/env bash
# provision.sh: runs once inside the bake guest (cloud-init runcmd) and turns the pinned Ubuntu
# 24.04 cloud image into the base disk every sfab VM guest boots from. bake.sh embeds it in the
# bake's user-data with provision.env beside it. It needs the internet (the Ubuntu archive and
# pkgs.k8s.io); the nodes built from its result never do.
#
# What it does, in order:
#   0. points apt at the Ubuntu archive snapshot UBUNTU_SNAPSHOT (snapshot.ubuntu.com), when one
#      is pinned, so the same pins install the same packages. The snapshot service is slow and
#      answers 5xx now and then, so apt reads only the indexes the bake needs (main and universe,
#      no translations or command indexes), every download retries, and the packages are fetched
#      several at a time before apt installs them from its cache (it checks each one's sha256);
#   1. holds every installed kernel package, so nothing below pulls a newer kernel than the one
#      linux-modules-extra is installed for;
#   2. installs containerd, the storage clients (open-iscsi, multipath-tools, nfs-common,
#      nvme-cli), lldpd, the lab's diagnostic tools and linux-modules-extra for the running kernel;
#   3. installs kubelet, kubeadm and kubectl at K8S_VERSION (package K8S_PKG_VERSION) from
#      pkgs.k8s.io, with the CNI plugins and cri-tools at their pinned versions, and holds them;
#   4. configures containerd (systemd cgroups, one registry config_path directory), the kernel
#      modules and sysctls Kubernetes needs, sshd without socket activation or passwords;
#   5. turns off unattended upgrades and the apt timers, removes snapd;
#   6. writes the package manifest, puts the image's own apt sources back, cleans cloud-init's
#      state and the machine id so every node boots as a new instance, trims the disk and powers
#      off.
# bake.sh shares a directory with the guest over 9p (tag sfabxfer): this script writes its log,
# the manifest and a status line there (SFAB-BAKE-OK, or SFAB-BAKE-FAIL with the line). The same
# status line goes to the serial console, for a bake whose share did not mount.
set -Eeuo pipefail

X=/mnt/sfab-xfer
mkdir -p "$X"
mount -t 9p -o trans=virtio,version=9p2000.L sfabxfer "$X" 2>/dev/null || X=""
exec > >(tee -a /var/log/sfab-provision.log ${X:+"$X/provision.log"}) 2>&1

say() { printf '%s\n' "$*"; printf '%s\n' "$*" > /dev/ttyS0 2>/dev/null || true; }
status() {
  if [ -n "$X" ]; then printf '%s\n' "$1" > "$X/status"; fi
  say "$1"
  sync
}
fail() {
  status "SFAB-BAKE-FAIL line $1"
  if [ -n "$X" ]; then umount -l "$X" 2>/dev/null || true; fi
  systemctl poweroff --no-block || poweroff -f
}
trap 'fail $LINENO' ERR

# shellcheck source=/dev/null
. /root/sfab-provision.env
: "${K8S_VERSION:?provision.env sets K8S_VERSION}"
K8S_MINOR=$(cut -d. -f1-2 <<< "$K8S_VERSION")
K8S_PKG=${K8S_PKG_VERSION:-${K8S_VERSION#v}-1.1}
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

say "sfab-bake: kernel $(uname -r), Kubernetes $K8S_VERSION (packages $K8S_PKG), archive snapshot ${UBUNTU_SNAPSHOT:-none}"

# retry CMD...: up to 8 tries, 10 s more between each (an until condition does not trip the ERR trap).
retry() {
  local n=1
  until "$@"; do
    [ "$n" -ge 8 ] && return 1
    say "sfab-bake: retry $n of: $*"
    sleep $((n * 10))
    n=$((n + 1))
  done
}
# prefetch PKG...: put the packages apt would download into its cache, PREFETCH_JOBS at a time,
# each checked by apt-helper against the hash --print-uris gives. apt checks every cached package
# against the signed index again before it installs it, and fetches whatever this missed.
PREFETCH_JOBS=${PREFETCH_JOBS:-8}
prefetch() {
  local cache=/var/cache/apt/archives
  # shellcheck disable=SC2016  # the sh -c script expands its own arguments
  "${APT[@]}" install --no-install-recommends --print-uris -qq "$@" \
    | sed -n "s/^'\([^']*\)' \([^ ]*\) [0-9]* \([A-Za-z0-9]*:[0-9a-f]*\)\$/\1 \2 \3/p" \
    | xargs -r -P "$PREFETCH_JOBS" -n 3 sh -c \
      '/usr/lib/apt/apt-helper -o Acquire::Retries=10 download-file "$1" "$0/partial/$2" "$3" >/dev/null 2>&1 && mv -f "$0/partial/$2" "$0/$2" || echo "prefetch missed $2"' \
      "$cache"
}
# fetch_install PKG...: prefetch, download the rest with retries, then install from the cache.
fetch_install() {
  prefetch "$@" || true
  retry "${APT[@]}" install --download-only --no-install-recommends "$@"
  "${APT[@]}" install --no-install-recommends "$@"
}

# 0. the pinned archive snapshot, and patient downloads
SOURCES=/etc/apt/sources.list.d/ubuntu.sources
cp "$SOURCES" /root/ubuntu.sources.image
printf '%s\n' 'Acquire::Retries "10";' 'APT::Update::Error-Mode "any";' 'Acquire::Languages "none";' \
  'Acquire::IndexTargets::deb::CNF::DefaultEnabled "false";' 'Acquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";' \
  'Acquire::IndexTargets::deb::DEP-11-icons::DefaultEnabled "false";' \
  'Acquire::IndexTargets::deb::DEP-11-icons-small::DefaultEnabled "false";' > /etc/apt/apt.conf.d/80sfab-bake
sed -i -E -e 's/^Components:.*/Components: main universe/' -e '/^Suites:/s/ noble-backports//' "$SOURCES"
if [ -n "${UBUNTU_SNAPSHOT:-}" ]; then
  sed -i -E "s#^URIs:.*#URIs: https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#" "$SOURCES"
  grep -q "snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/" "$SOURCES"
fi
say "sfab-bake: apt sources: $(grep -E '^(URIs|Suites|Components):' "$SOURCES" | tr '\n' ' ')"

# 1. the kernel stays the one this disk boots
mapfile -t kernel_pkgs < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-*' | awk '$1 ~ /^ii/ {print $2}')
apt-mark hold "${kernel_pkgs[@]}" >/dev/null

# 2. distribution packages
retry "${APT[@]}" update
fetch_install \
  "linux-modules-extra-$(uname -r)" \
  containerd open-iscsi multipath-tools nfs-common nvme-cli lldpd \
  ethtool iproute2 iputils-ping iputils-tracepath traceroute tcpdump iperf3 jq curl gnupg \
  ca-certificates dnsutils conntrack socat ebtables
apt-mark hold "linux-modules-extra-$(uname -r)" containerd >/dev/null

# 3. Kubernetes packages, pinned
install -d -m 0755 /etc/apt/keyrings
retry curl -fsSL --retry 5 --retry-delay 5 -o /root/kubernetes-release.key \
  "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key"
gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg < /root/kubernetes-release.key
rm -f /root/kubernetes-release.key
printf 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/%s/deb/ /\n' \
  "$K8S_MINOR" > /etc/apt/sources.list.d/kubernetes.list
retry "${APT[@]}" update
k8s=("kubelet=$K8S_PKG" "kubeadm=$K8S_PKG" "kubectl=$K8S_PKG")
k8s+=("kubernetes-cni${K8S_CNI_VERSION:+=$K8S_CNI_VERSION}" "cri-tools${CRI_TOOLS_VERSION:+=$CRI_TOOLS_VERSION}")
fetch_install "${k8s[@]}"
apt-mark hold kubelet kubeadm kubectl kubernetes-cni cri-tools >/dev/null

# 4. configuration
install -d -m 0755 /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
# One registry config_path directory: containerd 2.x ignores hosts.toml when config_path lists
# two directories (its packaged default does, for the CRI plugin and the transfer service), and
# 1.7 leaves the CRI plugin's empty. Every value that lists /etc/containerd/certs.d among several
# directories, and the CRI registry section's own, become that one directory.
sed -i -E "s#^([[:space:]]*config_path[[:space:]]*=[[:space:]]*)['\"][^'\"]*/etc/containerd/certs\.d[^'\"]*:[^'\"]*['\"]#\1\"/etc/containerd/certs.d\"#" \
  /etc/containerd/config.toml
awk '/^[[:space:]]*\[/ {sec = $0}
     sec ~ /registry\][[:space:]]*$/ && $1 == "config_path" {sub(/=.*/, "= \"/etc/containerd/certs.d\"")}
     {print}' /etc/containerd/config.toml > /etc/containerd/config.toml.new
mv /etc/containerd/config.toml.new /etc/containerd/config.toml
grep -q 'SystemdCgroup = true' /etc/containerd/config.toml
grep -q 'config_path = "/etc/containerd/certs.d"' /etc/containerd/config.toml
install -d -m 0755 /etc/containerd/certs.d
systemctl enable containerd

printf '%s\n' overlay br_netfilter iscsi_tcp nvme_tcp > /etc/modules-load.d/sfab.conf
printf '%s\n' 'net.ipv4.ip_forward = 1' 'net.bridge.bridge-nf-call-iptables = 1' \
  'net.bridge.bridge-nf-call-ip6tables = 1' > /etc/sysctl.d/90-sfab-k8s.conf

# multipathd may not claim the guest's own virtio disks; the CSI driver logs in to its LUNs.
printf '%s\n' 'defaults {' '    user_friendly_names yes' '    find_multipaths no' '}' \
  'blacklist {' '    devnode "^vd[a-z]"' '}' > /etc/multipath.conf
sed -i 's/^#\?node.session.scan = .*/node.session.scan = manual/' /etc/iscsi/iscsid.conf
systemctl enable multipathd lldpd
systemctl enable iscsid.socket 2>/dev/null || systemctl enable iscsid 2>/dev/null || true

systemctl disable ssh.socket 2>/dev/null || true
systemctl enable ssh.service
install -d -m 0755 /etc/ssh/sshd_config.d
printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' \
  > /etc/ssh/sshd_config.d/10-sfab.conf

# 5. nothing changes underneath a running lab
printf '%s\n' 'APT::Periodic::Update-Package-Lists "0";' 'APT::Periodic::Unattended-Upgrade "0";' \
  > /etc/apt/apt.conf.d/20auto-upgrades
systemctl disable apt-daily.timer apt-daily-upgrade.timer motd-news.timer 2>/dev/null || true
systemctl mask apt-daily.service apt-daily-upgrade.service unattended-upgrades.service 2>/dev/null || true
"${APT[@]}" purge snapd unattended-upgrades || true
"${APT[@]}" autoremove --purge || true
swapoff -a || true
sed -i '/[[:space:]]swap[[:space:]]/d' /etc/fstab

# 6. the record, then a clean first boot for every node
install -d -m 0755 /usr/share/sfab
dpkg-query -W -f='${Package} ${Version}\n' | LC_ALL=C sort > /usr/share/sfab/packages.txt
if [ -n "$X" ]; then cp /usr/share/sfab/packages.txt "$X/manifest.txt"; fi
say "sfab-bake: $(wc -l < /usr/share/sfab/packages.txt) packages; kubelet $(dpkg-query -W -f='${Version}' kubelet), containerd $(dpkg-query -W -f='${Version}' containerd)"
"${APT[@]}" clean
rm -rf /var/lib/apt/lists/*
mv -f /root/ubuntu.sources.image "$SOURCES"
rm -f /etc/apt/apt.conf.d/80sfab-bake
rm -f /root/sfab-provision.sh /root/sfab-provision.env
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
rm -f /etc/ssh/ssh_host_*
fstrim -av || true
trap - ERR
status "SFAB-BAKE-OK"
if [ -n "$X" ]; then umount -l "$X" 2>/dev/null || true; fi
systemctl poweroff --no-block
