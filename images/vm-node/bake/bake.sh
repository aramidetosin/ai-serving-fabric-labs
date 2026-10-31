#!/usr/bin/env bash
# bake.sh: bake the vm-node base disk. `make -C images vm-node-base` runs it inside the
# sfab/vm-node runtime image, with the bake directory bound at /out, the pinned cloud image
# read-only at /in/<UBUNTU_IMAGE> and this directory at /bake:
#
#   docker run --rm --device /dev/kvm -v <bake dir>:/out -v <cloud image>:/in/<name>:ro \
#     -v <bake>:/bake:ro -e UBUNTU_IMAGE=... -e UBUNTU_IMAGE_PATH=/in/<name> -e UBUNTU_SHA256=... \
#     -e UBUNTU_SNAPSHOT=... -e K8S_VERSION=... -e K8S_PKG_VERSION=... -e K8S_CNI_VERSION=... \
#     -e CRI_TOOLS_VERSION=... <runtime image> /bake/bake.sh
#
# It verifies the pinned cloud image (UBUNTU_IMAGE_PATH, default /out/cache/<UBUNTU_IMAGE>)
# against its sha256, boots it once on an overlay with user-data-bake.tmpl (QEMU user networking:
# the guest reaches the Ubuntu archive snapshot and pkgs.k8s.io through the container's network),
# waits for provision.sh to power the guest off, and flattens the overlay into /out/node.qcow2
# with its sha256 in /out/node.id. The package manifest lands in /out/node.manifest and the run's
# record in /out/node.pins. The same pins bake the same packages: Ubuntu's come from the archive
# snapshot UBUNTU_SNAPSHOT, and the Kubernetes packages are pinned by version.
set -euo pipefail

OUT=${BAKE_OUT:-/out}
BAKE=${BAKE_DIR:-/bake}
: "${UBUNTU_IMAGE:?set UBUNTU_IMAGE, the cloud image file under $OUT/cache}"
: "${UBUNTU_SHA256:?set UBUNTU_SHA256, the cloud image sha256 from spec/versions.yaml}"
: "${K8S_VERSION:?set K8S_VERSION, for example v1.35.8}"
DISK_GIB=${BAKE_DISK_GIB:-12}
MEM=${BAKE_MEMORY_MB:-4096}
SMP=${BAKE_SMP:-4}
TIMEOUT=${BAKE_TIMEOUT_S:-3600}

log() { printf '[bake] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }

[ -c /dev/kvm ] || die "no /dev/kvm (run the container with --device /dev/kvm)"
src="${UBUNTU_IMAGE_PATH:-$OUT/cache/$UBUNTU_IMAGE}"
[ -r "$src" ] || die "no $src (make -C images vm-node-fetch finds or downloads it)"
have=$(sha256sum < "$src" | cut -c1-64)
[ "$have" = "$UBUNTU_SHA256" ] || die "$src has sha256 $have, the pin says $UBUNTU_SHA256"

work="$OUT/work"
rm -rf "$work"
mkdir -p "$work/seed" "$work/xfer"
qemu-img create -q -f qcow2 -b "$src" -F qcow2 "$work/disk.qcow2" "${DISK_GIB}G"

PROVISION_B64=$(base64 -w0 < "$BAKE/provision.sh")
PROVISION_ENV_B64=$(printf 'K8S_VERSION=%s\nK8S_PKG_VERSION=%s\nK8S_CNI_VERSION=%s\nCRI_TOOLS_VERSION=%s\nUBUNTU_SNAPSHOT=%s\n' \
  "$K8S_VERSION" "${K8S_PKG_VERSION:-}" "${K8S_CNI_VERSION:-}" "${CRI_TOOLS_VERSION:-}" "${UBUNTU_SNAPSHOT:-}" | base64 -w0)
export PROVISION_B64 PROVISION_ENV_B64
# shellcheck disable=SC2016  # envsubst takes the variable names literally
envsubst '${PROVISION_B64} ${PROVISION_ENV_B64}' < "$BAKE/user-data-bake.tmpl" > "$work/seed/user-data"
printf 'instance-id: sfab-bake\nlocal-hostname: sfab-bake\n' > "$work/seed/meta-data"
genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rational-rock "$work/seed"

log "booting $UBUNTU_IMAGE to provision Kubernetes $K8S_VERSION from archive snapshot ${UBUNTU_SNAPSHOT:-<none: the live archive>} (at most ${TIMEOUT}s; console in $work/console.log)"
qemu-system-x86_64 -name sfab-bake -machine q35,accel=kvm -cpu host -smp "$SMP" -m "$MEM" \
  -nodefaults -no-user-config -display none -no-reboot \
  -serial "file:$work/console.log" \
  -drive "file=$work/disk.qcow2,if=virtio,format=qcow2,discard=unmap" \
  -drive "file=$work/seed.iso,if=virtio,format=raw,readonly=on" \
  -fsdev "local,id=xfer,path=$work/xfer,security_model=none" -device virtio-9p-pci,fsdev=xfer,mount_tag=sfabxfer \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile= \
  -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 &
qpid=$!
trap 'kill "$qpid" 2>/dev/null || true' EXIT

t=0
while kill -0 "$qpid" 2>/dev/null; do
  if [ "$t" -ge "$TIMEOUT" ]; then
    kill "$qpid" 2>/dev/null || true
    die "the bake guest did not power off within ${TIMEOUT}s (see $work/console.log)"
  fi
  if [ $((t % 60)) -eq 0 ] && [ -f "$work/xfer/provision.log" ]; then
    log "${t}s: $(tail -n 1 "$work/xfer/provision.log" | cut -c1-150)"
  fi
  sleep 5
  t=$((t + 5))
done
wait "$qpid" || true
trap - EXIT

tr -d '\r' < "$work/console.log" > "$OUT/bake-console.log"
if [ -f "$work/xfer/provision.log" ]; then cp "$work/xfer/provision.log" "$OUT/bake-provision.log"; fi
result=$(head -n 1 "$work/xfer/status" 2>/dev/null || true)
if [ -z "$result" ]; then
  result=$(grep -o 'SFAB-BAKE-[A-Z]*.*' "$OUT/bake-console.log" | tail -n 1 || true)
fi
case "$result" in
  SFAB-BAKE-OK*) ;;
  *) die "the bake failed (${result:-no status}); see $OUT/bake-provision.log and $OUT/bake-console.log" ;;
esac
[ -s "$work/xfer/manifest.txt" ] || die "the bake reported OK but wrote no manifest"
cp "$work/xfer/manifest.txt" "$OUT/node.manifest"

log "flattening the disk"
qemu-img convert -O qcow2 "$work/disk.qcow2" "$OUT/node.qcow2.tmp"
id=$(sha256sum < "$OUT/node.qcow2.tmp" | cut -c1-64)
mv -f "$OUT/node.qcow2.tmp" "$OUT/node.qcow2"
printf '%s\n' "$id" > "$OUT/node.id"
{
  printf 'ubuntu_image %s\nubuntu_sha256 %s\nubuntu_snapshot %s\n' "$UBUNTU_IMAGE" "$UBUNTU_SHA256" "${UBUNTU_SNAPSHOT:-none}"
  printf 'k8s_version %s\nnode_qcow2_sha256 %s\n' "$K8S_VERSION" "$id"
  grep -E '^(containerd|cri-tools|kubeadm|kubectl|kubelet|kubernetes-cni|linux-image-[0-9].*|linux-modules-extra-.*) ' "$OUT/node.manifest" || true
} > "$OUT/node.pins"
rm -rf "$work"
log "base disk ready: $OUT/node.qcow2 ($(du -h "$OUT/node.qcow2" | cut -f1), sha256 $id)"
