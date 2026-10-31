#!/usr/bin/env bash
# cluster-bootstrap.sh: bring this guest into the lab's Kubernetes cluster (sfab-cluster.service,
# Restart=on-failure). Idempotent: every boot runs it again, and each step that holds acts on
# nothing. It reads the files render/k8s.py rendered for this node, which vm-init.sh seeds into
# /etc/sfab/k8s (cluster.env names the role, the files and the pins), and the lab's shared
# directory, which every guest mounts at /shared:
#
#   /shared/cluster/ca/       ca.crt, ca.key (0600), root.crt: the lab's Kubernetes intermediate and
#                             root, which sfab-ca publishes on the lab host before the deploy. The key is there only
#                             until every control node has joined (finish runs sfab-ca retract), so
#                             a node that holds the lab's CA already takes only the certificates
#   /shared/cluster/kubeadm.env  SFAB_KUBEADM_TOKEN=<token> (0600), the lab's join token, which the boot
#                             stage writes from state/secrets.env; the init node makes one if none is there
#   /shared/cluster/pki/      written by the init node: the keys every control node shares (sa.key,
#                             sa.pub, front-proxy-ca, etcd-ca, and with Secrets encrypted at rest
#                             the API server's EncryptionConfiguration as encryption-config.key),
#                             so a control node joins without uploaded certificates that expire; the
#                             keys leave again with the retract, and the init node publishes them at
#                             its next run
#
# init (the init node):
#   1. the lab's Kubernetes intermediate as the cluster CA (/etc/kubernetes/pki/ca.crt and ca.key);
#      a cluster made from another CA is refused (a new lab CA needs make wipe). With Secrets
#      encrypted at rest (CLUSTER_ENCRYPTION_CONFIG), the API server's EncryptionConfiguration: made
#      once, at the first init, with a key of 32 random bytes for the provider cluster.env names and
#      identity after it (so a Secret written before reads back); kept as it is from then on, since
#      etcd's Secrets need that key. It is never printed.
#   2. when no cluster exists: kubeadm reset, then kube-vip's static pod on super-admin.conf (the only
#      kubeconfig that works while kubeadm init runs), the API server's certificate made first,
#      verified against the lab root (the intermediate's name constraints included) and followed by
#      the intermediate, so a client that trusts only the root can build the chain; then kubeadm
#      init. A failed init is reset for the next try.
#   3. the chain again (kubeadm certs renew drops it), and kube-vip moved to admin.conf
#   4. the lab's join token, with no expiry; the shared keys published for the control nodes
#   5. the API's chain checked: a kubeconfig with the API through the VIP and the lab root as its only
#      trust, made in a 0600 file under the run directory and removed after (no kubeconfig leaves this
#      node: the harness's kubectl runs here with admin.conf, and each operator's on the bastion carries
#      a short-lived client certificate the finish stage issues here)
#   6. the Gateway API CRDs, established before Cilium: its operator turns its Gateway controller
#      on only when they exist as it starts
#   7. helm, copied out of its pinned image (pulled through the in-lab registry: the base disk
#      carries no helm), then the Cilium release from the registry's OCI chart, installed or
#      upgraded only when the chart or the values changed; then this node's agent, the operator and
#      this node Ready
# join-control and join-worker:
#   1. when the node has not joined: wait for the API, kubeadm reset, then (control) the cluster CA
#      and the shared keys (the EncryptionConfiguration among them); kubeadm join from a 0600 copy of the rendered configuration with the
#      token and the CA pin appended, the only values not rendered; the copy is removed after
#   2. (control) the chain on the API server's certificate, and kube-vip on admin.conf
#
# The token is never printed. SFAB_K8S_DIR, SFAB_SHARED_CLUSTER, SFAB_KUBE_DIR, SFAB_STATE_DIR,
# SFAB_RUN_DIR and SFAB_BIN_DIR move the directories, and SFAB_WAIT_S and SFAB_POLL_S the waits
# (the tests use them, with stand-ins for kubeadm, kubectl, crictl, ctr and curl).
set -euo pipefail

K8S_DIR=${SFAB_K8S_DIR:-/etc/sfab/k8s}
KDIR=${SFAB_KUBE_DIR:-/etc/kubernetes}
STATE=${SFAB_STATE_DIR:-/var/lib/sfab/cluster}
RUN=${SFAB_RUN_DIR:-/run/sfab}
BIN=${SFAB_BIN_DIR:-/usr/local/bin}
WAIT_S=${SFAB_WAIT_S:-1800}
POLL_S=${SFAB_POLL_S:-10}
# The keys every control node shares, under /etc/kubernetes/pki (published flat: etcd/ca.crt is etcd-ca.crt).
SHARED_KEYS="sa.key sa.pub front-proxy-ca.crt front-proxy-ca.key etcd/ca.crt etcd/ca.key"
# The API server's EncryptionConfiguration as the control nodes share it: a .key name, so sfab-ca
# retract removes it from /shared with the other keys.
ENC_SHARED=encryption-config.key

CHANGED=0
TOKEN=""
HELM=""

log() { printf '[cluster-bootstrap] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }

# put <mode> <src> <dst>: install src at dst when the content differs (CHANGED=1), and set the mode.
put() {
  local mode=$1 src=$2 dst=$3
  CHANGED=0
  if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
    chmod "$mode" "$dst"
    return 0
  fi
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst.sfab-new"
  chmod "$mode" "$dst.sfab-new"
  mv -f "$dst.sfab-new" "$dst"
  CHANGED=1
}

# wait_for <what> <seconds> <command...>: run the command until it succeeds, at most that long.
wait_for() {
  local what=$1 max=$2 t=0 n=0
  shift 2
  until "$@" >/dev/null 2>&1; do
    if [ "$t" -ge "$max" ]; then
      log "gave up after ${max}s waiting for $what"
      return 1
    fi
    if [ $((n % 6)) -eq 0 ]; then log "waiting for $what"; fi
    sleep "$POLL_S"
    t=$((t + POLL_S))
    n=$((n + 1))
  done
}

# retry <tries> <pause> <command...>: the command's own output is kept; the last failure stands.
retry() {
  local tries=$1 pause=$2 i=1
  shift 2
  until "$@"; do
    if [ "$i" -ge "$tries" ]; then return 1; fi
    log "retry $i of $((tries - 1)) in ${pause}s: $1 ${2:-}"
    sleep "$pause"
    i=$((i + 1))
  done
}

# ------------------------------------------------------------------------------------------
load() {
  local f=$K8S_DIR/cluster.env v
  [ -r "$f" ] || die "no $f: this node has no cluster files (render/k8s.py)"
  set -a
  # shellcheck source=/dev/null
  . "$f"
  set +a
  for v in CLUSTER_NAME CLUSTER_NODE CLUSTER_ROLE CLUSTER_ADDRESS CLUSTER_API_ENDPOINT CLUSTER_API_VIP \
           CLUSTER_API_PORT CLUSTER_SHARED CLUSTER_KUBEADM CLUSTER_CRI; do
    [ -n "${!v:-}" ] || die "$f sets no $v"
  done
  case $CLUSTER_ROLE in
    init) for v in CLUSTER_KUBE_VIP CLUSTER_KUBE_VIP_INIT CLUSTER_CRDS CLUSTER_CILIUM_VALUES CLUSTER_CILIUM_RELEASE \
                   CLUSTER_CILIUM_NAMESPACE CLUSTER_CILIUM_CHART CLUSTER_CILIUM_VERSION CLUSTER_HELM_IMAGE \
                   CLUSTER_HELM_IMAGE_NAME CLUSTER_HELM_VERSION CLUSTER_CHAIN_SERVER; do
            [ -n "${!v:-}" ] || die "$f sets no $v (the init node's files)"
          done ;;
    join-control|join-worker)
      [ -n "${CLUSTER_JOIN_TAIL:-}" ] || die "$f sets no CLUSTER_JOIN_TAIL"
      if [ "$CLUSTER_ROLE" = join-control ] && [ -z "${CLUSTER_KUBE_VIP:-}" ]; then die "$f sets no CLUSTER_KUBE_VIP"; fi ;;
    *) die "$f: CLUSTER_ROLE $CLUSTER_ROLE is not init, join-control or join-worker" ;;
  esac
  SHARED=${SFAB_SHARED_CLUSTER:-$CLUSTER_SHARED}
  # the EncryptionConfiguration under /etc/kubernetes follows SFAB_KUBE_DIR (the tests move it)
  if [ -n "${CLUSTER_ENCRYPTION_CONFIG:-}" ]; then CLUSTER_ENCRYPTION_CONFIG=${CLUSTER_ENCRYPTION_CONFIG/#\/etc\/kubernetes/$KDIR}; fi
  KUBEADM_CFG=$K8S_DIR/$CLUSTER_KUBEADM
  ADMIN=$KDIR/admin.conf
  [ -r "$KUBEADM_CFG" ] || die "no $KUBEADM_CFG"
}

kc() { kubectl --kubeconfig "$ADMIN" "$@"; }
control() { [ "$CLUSTER_ROLE" != join-worker ]; }
cluster_exists() { [ -s "$ADMIN" ] && [ -s "$KDIR/manifests/kube-apiserver.yaml" ]; }
joined() { [ -s "$KDIR/kubelet.conf" ]; }
crt_pub() { openssl x509 -in "$1" -noout -pubkey 2>/dev/null; }
key_pub() { openssl pkey -in "$1" -pubout 2>/dev/null; }
subject() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//'; }
issuer() { openssl x509 -in "$1" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//'; }

# ------------------------------------------------------------------------------------------
# the token, the CA and the shared keys

token_file_ready() { [ -s "$SHARED/kubeadm.env" ]; }

read_token() {
  local f=$SHARED/kubeadm.env t
  if ! token_file_ready && [ "$CLUSTER_ROLE" = init ]; then
    log "no $f from the boot stage: making a join token for this cluster"
    mkdir -p "$SHARED"
    t=$(kubeadm token generate)
    (umask 077 && printf 'SFAB_KUBEADM_TOKEN=%s\n' "$t" > "$f.sfab-new" && mv -f "$f.sfab-new" "$f")
  fi
  wait_for "$f (the lab's join token)" "$WAIT_S" token_file_ready || return 1
  TOKEN=$(sed -n 's/^SFAB_KUBEADM_TOKEN=//p' "$f" | tail -n 1)
  [[ $TOKEN =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "$f holds no SFAB_KUBEADM_TOKEN of the form [a-z0-9]{6}.[a-z0-9]{16}"
}

ca_ready() { [ -s "$SHARED/ca/ca.crt" ] && [ -s "$SHARED/ca/ca.key" ] && [ -s "$SHARED/ca/root.crt" ]; }

# ca_held: this node holds the lab's cluster CA already (the published certificate, with its key),
# so the key need not be under /shared: after the joins finish retracts it.
ca_held() {
  local src=$SHARED/ca
  [ -s "$src/ca.crt" ] && [ -s "$src/root.crt" ] && [ -s "$KDIR/pki/ca.key" ] && cmp -s "$src/ca.crt" "$KDIR/pki/ca.crt" &&
    [ "$(crt_pub "$src/ca.crt")" = "$(key_pub "$KDIR/pki/ca.key")" ]
}

place_ca() {
  local src=$SHARED/ca
  if ca_held; then
    chmod 0600 "$KDIR/pki/ca.key"
    return 0
  fi
  wait_for "the lab's Kubernetes CA in $src (sfab-ca init on the lab host)" "$WAIT_S" ca_ready || return 1
  [ "$(crt_pub "$src/ca.crt")" = "$(key_pub "$src/ca.key")" ] || die "$src/ca.crt does not match $src/ca.key"
  if [ -s "$KDIR/pki/ca.crt" ] && cluster_exists && [ "$(crt_pub "$KDIR/pki/ca.crt")" != "$(crt_pub "$src/ca.crt")" ]; then
    die "this cluster was made from another CA than the lab's ($src/ca.crt): a new lab CA needs make wipe"
  fi
  mkdir -p "$KDIR/pki"
  put 0644 "$src/ca.crt" "$KDIR/pki/ca.crt"
  if [ "$CHANGED" = 1 ]; then log "cluster CA: $(subject "$src/ca.crt")"; fi
  put 0600 "$src/ca.key" "$KDIR/pki/ca.key"
}

keys_ready() {
  local f
  for f in $SHARED_KEYS; do [ -s "$SHARED/pki/${f//\//-}" ] || return 1; done
  if encryption_on; then [ -s "$SHARED/pki/$ENC_SHARED" ] || return 1; fi
}

# ------------------------------------------------------------------------------------------
# Secrets at rest

encryption_on() { [ -n "${CLUSTER_ENCRYPTION_CONFIG:-}" ]; }

# make_encryption: the init node's EncryptionConfiguration, made once. A node that holds one keeps
# it: the Secrets in etcd were written with its key.
make_encryption() {
  local f=${CLUSTER_ENCRYPTION_CONFIG:-} prov=${CLUSTER_ENCRYPTION_PROVIDER:-secretbox} res k r
  encryption_on || return 0
  if [ -s "$f" ]; then
    chmod 0600 "$f"
    return 0
  fi
  case $prov in secretbox|aescbc|aesgcm) ;; *) die "CLUSTER_ENCRYPTION_PROVIDER $prov is not secretbox, aescbc or aesgcm" ;; esac
  res=${CLUSTER_ENCRYPTION_RESOURCES:-secrets}
  mkdir -p "$(dirname "$f")"
  chmod 0700 "$(dirname "$f")"
  k=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  [ "${#k}" = 44 ] || die "could not make a 32-byte key for the EncryptionConfiguration"
  (
    umask 077
    {
      printf 'apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources:\n'
      for r in ${res//,/ }; do printf '      - %s\n' "$r"; done
      printf '    providers:\n      - %s:\n          keys:\n            - name: key1\n              secret: %s\n      - identity: {}\n' "$prov" "$k"
    } > "$f.sfab-new"
    mv -f "$f.sfab-new" "$f"
  )
  k=""
  log "Secrets at rest: an EncryptionConfiguration with a new $prov key for ${res//,/, } (key1; identity after it)"
}

place_encryption() {
  local f=${CLUSTER_ENCRYPTION_CONFIG:-}
  encryption_on || return 0
  mkdir -p "$(dirname "$f")"
  chmod 0700 "$(dirname "$f")"
  put 0600 "$SHARED/pki/$ENC_SHARED" "$f"
  if [ "$CHANGED" = 1 ]; then log "Secrets at rest: the cluster's EncryptionConfiguration placed from $SHARED/pki"; fi
}

publish_keys() {
  local f mode n=0
  mkdir -p "$SHARED/pki"
  chmod 0700 "$SHARED/pki"
  for f in $SHARED_KEYS; do
    mode=0644
    case $f in *.key) mode=0600 ;; esac
    put "$mode" "$KDIR/pki/$f" "$SHARED/pki/${f//\//-}"
    n=$((n + CHANGED))
  done
  if encryption_on; then
    [ -s "$CLUSTER_ENCRYPTION_CONFIG" ] || die "no $CLUSTER_ENCRYPTION_CONFIG on the init node to share"
    put 0600 "$CLUSTER_ENCRYPTION_CONFIG" "$SHARED/pki/$ENC_SHARED"
    n=$((n + CHANGED))
  fi
  if [ "$n" -gt 0 ]; then log "the control nodes' shared keys published in $SHARED/pki"; fi
}

place_keys() {
  local f mode
  wait_for "the shared keys in $SHARED/pki (the init node publishes them)" "$WAIT_S" keys_ready || return 1
  for f in $SHARED_KEYS; do
    mode=0644
    case $f in *.key) mode=0600 ;; esac
    put "$mode" "$SHARED/pki/${f//\//-}" "$KDIR/pki/$f"
  done
  place_encryption
}

# ------------------------------------------------------------------------------------------
# the API server's certificate

# verify_apiserver: the certificate verifies against the lab root, through the intermediate, with
# the intermediate's name constraints applied to every name kubeadm put in it.
verify_apiserver() {
  local crt=$KDIR/pki/apiserver.crt out why
  if out=$(openssl verify -CAfile "$SHARED/ca/root.crt" -untrusted "$KDIR/pki/ca.crt" "$crt" 2>&1); then return 0; fi
  why=$(printf '%s\n' "$out" | grep -m 1 -i 'error' || printf '%s\n' "$out" | tail -n 1)
  die "the API server's certificate does not verify against the lab root ($why). The Kubernetes intermediate's name constraints must permit every name kubeadm puts in it, this node's name ($CLUSTER_NODE) included: spec ca.intermediates"
}

# chain: the API server's certificate followed by the intermediate that signed it.
chain() {
  local crt=$KDIR/pki/apiserver.crt ca=$KDIR/pki/ca.crt
  [ -s "$crt" ] || return 0
  if [ "$(grep -c 'BEGIN CERTIFICATE' "$crt")" -ge 2 ]; then return 0; fi
  [ "$(issuer "$crt")" = "$(subject "$ca")" ] || die "$crt was not issued by $(subject "$ca")"
  cat "$crt" "$ca" > "$crt.sfab-new"
  chmod 0644 "$crt.sfab-new"
  mv -f "$crt.sfab-new" "$crt"
  log "the API server's certificate now carries its intermediate ($(subject "$ca"))"
}

kube_vip() {  # kube_vip <file in K8S_DIR>: kube-vip's static pod, replaced only when it differs
  mkdir -p "$KDIR/manifests"
  put 0644 "$K8S_DIR/$1" "$KDIR/manifests/kube-vip.yaml"
  if [ "$CHANGED" = 1 ]; then log "kube-vip: $1"; fi
}

# ------------------------------------------------------------------------------------------
# init

init_cluster() {
  if cluster_exists; then
    log "the cluster exists (kubeadm init ran before)"
    return 0
  fi
  log "kubeadm init on $CLUSTER_NODE ($CLUSTER_ADDRESS), control-plane endpoint $CLUSTER_API_ENDPOINT"
  kubeadm reset -f >/dev/null 2>&1 || true
  place_ca
  make_encryption
  kube_vip "$CLUSTER_KUBE_VIP_INIT"
  kubeadm init phase certs apiserver --config "$KUBEADM_CFG"
  verify_apiserver
  chain
  if ! kubeadm init --config "$KUBEADM_CFG" --skip-token-print --skip-certificate-key-print; then
    log "kubeadm init failed: resetting for the next try"
    kubeadm reset -f >/dev/null 2>&1 || true
    return 1
  fi
}

api_ready() { kc get --raw /readyz; }

ensure_token() {
  local id=${TOKEN%%.*} secret=${TOKEN#*.} have
  have=$(kc -n kube-system get secret "bootstrap-token-$id" -o jsonpath='{.data.token-secret}' 2>/dev/null | base64 -d 2>/dev/null || true)
  if [ "$have" = "$secret" ]; then return 0; fi
  if [ -n "$have" ]; then kubeadm token delete --kubeconfig "$ADMIN" "$id" >/dev/null 2>&1 || true; fi
  kubeadm token create "$TOKEN" --ttl 0 --description "the lab join token" --kubeconfig "$ADMIN" >/dev/null
  log "the lab's join token is in place, with no expiry"
}

check_chain() {
  local tmp err
  mkdir -p "$RUN"
  tmp=$(umask 077 && mktemp "$RUN/kubeconfig.XXXXXX")
  (umask 077 && cp "$ADMIN" "$tmp")
  kubectl --kubeconfig "$tmp" config set-cluster "$CLUSTER_NAME" --server="$CLUSTER_CHAIN_SERVER" \
    --certificate-authority="$SHARED/ca/root.crt" --embed-certs=true >/dev/null
  if ! err=$(kubectl --kubeconfig "$tmp" get --raw /readyz 2>&1 >/dev/null); then
    rm -f "$tmp"
    die "the API at $CLUSTER_CHAIN_SERVER does not verify against the lab root: $err"
  fi
  rm -f "$tmp"
  # a kubeconfig an earlier version of this script published for the bastion is removed
  rm -f "$SHARED/kubeconfig" "$SHARED/ready"
  log "the API at $CLUSTER_CHAIN_SERVER verifies against the lab root alone"
}

crds() {
  local f=$K8S_DIR/$CLUSTER_CRDS
  retry 30 10 kc apply --server-side --force-conflicts -f "$f" >/dev/null
  retry 10 10 kc wait --for=condition=Established --timeout=60s -f "$f" >/dev/null
  log "Gateway API ${CLUSTER_GATEWAY_API_VERSION:-} CRDs established"
}

helm_version() { "$1" version --template '{{.Version}}' 2>/dev/null; }

# helm_bin: helm copied out of its pinned image by a short-lived container of that image, with a
# directory of this node bound at /out. containerd 2.2.1's `ctr images mount` cannot be used: its
# mount manager's bind mount fails with "no such device" (M2's first deploy, dev/m2/RESULTS.md, problem 1).
helm_bin() {
  local h=$BIN/helm out c=sfab-helm-copy sock=${CLUSTER_CRI#unix://}
  if [ -x "$h" ] && [ "$(helm_version "$h")" = "$CLUSTER_HELM_VERSION" ]; then
    HELM=$h
    return 0
  fi
  log "helm $CLUSTER_HELM_VERSION from $CLUSTER_HELM_IMAGE"
  retry 30 10 crictl --runtime-endpoint "$CLUSTER_CRI" pull "$CLUSTER_HELM_IMAGE" >/dev/null
  mkdir -p "$RUN" "$BIN"
  out=$(mktemp -d "$RUN/helm-image.XXXXXX")
  # a copy container left by a run that was cut short
  ctr --address "$sock" -n k8s.io tasks rm -f "$c" >/dev/null 2>&1 || true
  ctr --address "$sock" -n k8s.io containers rm "$c" >/dev/null 2>&1 || true
  # shellcheck disable=SC2016 # expanded by the image's shell
  if ! ctr --address "$sock" -n k8s.io run --rm --mount "type=bind,src=$out,dst=/out,options=rbind:rw" \
    "$CLUSTER_HELM_IMAGE_NAME" "$c" sh -c 'for p in /usr/bin/helm /usr/local/bin/helm /bin/helm; do if [ -f "$p" ]; then cp "$p" /out/helm; exit $?; fi; done; exit 1' >/dev/null ||
    [ ! -s "$out/helm" ]; then
    rm -rf "$out"
    die "no helm binary in $CLUSTER_HELM_IMAGE"
  fi
  cp "$out/helm" "$h.sfab-new"
  chmod 0755 "$h.sfab-new"
  mv -f "$h.sfab-new" "$h"
  rm -rf "$out"
  [ "$(helm_version "$h")" = "$CLUSTER_HELM_VERSION" ] || die "the helm in $CLUSTER_HELM_IMAGE is not $CLUSTER_HELM_VERSION"
  HELM=$h
}

hc() {
  KUBECONFIG=$ADMIN HELM_CACHE_HOME=$STATE/helm/cache HELM_CONFIG_HOME=$STATE/helm/config \
    HELM_DATA_HOME=$STATE/helm/data "$HELM" "$@"
}

cilium_deployed() {
  hc list -n "$CLUSTER_CILIUM_NAMESPACE" --deployed --filter "^${CLUSTER_CILIUM_RELEASE}\$" -o json 2>/dev/null |
    grep -qF "\"chart\":\"cilium-$CLUSTER_CILIUM_VERSION\""
}

cilium_agent_ready() {
  kc -n "$CLUSTER_CILIUM_NAMESPACE" get pods -l k8s-app=cilium --field-selector "spec.nodeName=$CLUSTER_NODE" \
    -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}' | grep -qx True
}

cilium() {
  local values=$K8S_DIR/$CLUSTER_CILIUM_VALUES want have flags=()
  want=$({ printf '%s %s\n' "$CLUSTER_CILIUM_CHART" "$CLUSTER_CILIUM_VERSION"; cat "$values"; } | sha)
  have=$(cat "$STATE/cilium.applied" 2>/dev/null || true)
  if [ "$want" = "$have" ] && cilium_deployed; then
    log "Cilium $CLUSTER_CILIUM_VERSION is deployed with these values"
  else
    if [ "${CLUSTER_HELM_PLAIN_HTTP:-1}" = 1 ]; then flags+=(--plain-http); fi
    if [ -n "${CLUSTER_HELM_CA_FILE:-}" ]; then flags+=(--ca-file "$CLUSTER_HELM_CA_FILE"); fi
    retry 5 30 hc upgrade --install "$CLUSTER_CILIUM_RELEASE" "$CLUSTER_CILIUM_CHART" --version "$CLUSTER_CILIUM_VERSION" \
      -n "$CLUSTER_CILIUM_NAMESPACE" -f "$values" "${flags[@]}" --timeout 20m >/dev/null
    printf '%s\n' "$want" > "$STATE/cilium.applied"
    log "Cilium $CLUSTER_CILIUM_VERSION installed from $CLUSTER_CILIUM_CHART (release $CLUSTER_CILIUM_NAMESPACE/$CLUSTER_CILIUM_RELEASE)"
  fi
  wait_for "Cilium's agent on $CLUSTER_NODE" "$WAIT_S" cilium_agent_ready || return 1
  wait_for "the Cilium operator" "$WAIT_S" kc -n "$CLUSTER_CILIUM_NAMESPACE" wait --for=condition=Available deploy/cilium-operator --timeout=10s || return 1
  wait_for "$CLUSTER_NODE Ready" "$WAIT_S" kc wait --for=condition=Ready "node/$CLUSTER_NODE" --timeout=10s || return 1
  log "Cilium's agent and operator ready, $CLUSTER_NODE Ready"
}

init_node() {
  read_token
  place_ca
  if cluster_exists && encryption_on && [ ! -s "$CLUSTER_ENCRYPTION_CONFIG" ]; then
    die "the cluster exists but $CLUSTER_ENCRYPTION_CONFIG does not: its Secrets cannot be read without their key (make wipe starts a new cluster)"
  fi
  init_cluster
  chain
  kube_vip "$CLUSTER_KUBE_VIP"
  wait_for "the API through $CLUSTER_API_ENDPOINT" "$WAIT_S" api_ready || return 1
  ensure_token
  publish_keys
  check_chain
  crds
  helm_bin
  cilium
}

# ------------------------------------------------------------------------------------------
# join

api_answers() { curl -sk --max-time 5 "https://$CLUSTER_API_ENDPOINT/readyz" | grep -qx ok; }

# join_config <out>: the rendered JoinConfiguration with the token and the CA pin appended to the
# bootstrapToken mapping it ends with, in a 0600 file.
join_config() {
  local out=$1 pin
  [ "$(tail -n 1 "$KUBEADM_CFG")" = "$CLUSTER_JOIN_TAIL" ] || die "$KUBEADM_CFG does not end with its bootstrapToken mapping (run make render)"
  pin=$(openssl x509 -in "$SHARED/ca/ca.crt" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | sha)
  [ "${#pin}" = 64 ] || die "could not read the public key of $SHARED/ca/ca.crt"
  mkdir -p "$RUN"
  (umask 077 && { cat "$KUBEADM_CFG"; printf '    token: "%s"\n    caCertHashes:\n    - "sha256:%s"\n' "$TOKEN" "$pin"; } > "$out")
}

join_node() {
  local cfg=$RUN/kubeadm-join.yaml
  if joined; then
    log "$CLUSTER_NODE has joined (kubelet.conf exists)"
  else
    wait_for "the API at $CLUSTER_API_ENDPOINT" "$WAIT_S" api_answers || return 1
    read_token
    wait_for "the lab's Kubernetes CA in $SHARED/ca" "$WAIT_S" ca_ready || return 1
    kubeadm reset -f >/dev/null 2>&1 || true
    # A worker takes the CA from the cluster: kubeadm refuses a ca.crt that is already there.
    if control; then
      place_ca
      place_keys
    fi
    join_config "$cfg"
    if ! kubeadm config validate --config "$cfg" >/dev/null; then
      rm -f "$cfg"
      die "$cfg is not a valid kubeadm configuration"
    fi
    log "kubeadm join as $CLUSTER_ROLE through $CLUSTER_API_ENDPOINT, the CA pinned"
    if ! kubeadm join --config "$cfg"; then
      rm -f "$cfg"
      log "kubeadm join failed: resetting for the next try"
      kubeadm reset -f >/dev/null 2>&1 || true
      return 1
    fi
    rm -f "$cfg"
  fi
  if control; then
    verify_apiserver
    chain
    kube_vip "$CLUSTER_KUBE_VIP"
  fi
}

# ------------------------------------------------------------------------------------------
# models_mount: on a node whose seed carries the models share (vm-init.sh: a kubelet drop-in that
# requires the mount), the share mounted before kubeadm starts kubelet; at a later boot systemd
# mounts it first by itself.
models_mount() {
  local conf=/etc/systemd/system/kubelet.service.d/20-sfab-models.conf path unit
  [ -f "$conf" ] || return 0
  path=$(sed -n 's/^RequiresMountsFor=//p' "$conf" | head -n 1)
  [ -n "$path" ] || return 0
  unit=$(systemd-escape -p --suffix=mount "$path")
  systemctl start "$unit" || die "the models share $unit did not mount"
  mountpoint -q "$path" || die "$path is not a mount point after $unit started"
  log "models share mounted read-only at $path ($(find "$path" -maxdepth 1 -name '*.gguf' | wc -l) GGUF file(s))"
}

main() {
  load
  models_mount
  mkdir -p "$STATE" "$RUN"
  log "$CLUSTER_NODE: $CLUSTER_ROLE in $CLUSTER_NAME, API $CLUSTER_API_ENDPOINT (VIP $CLUSTER_API_VIP)"
  case $CLUSTER_ROLE in
    init) init_node ;;
    *) join_node ;;
  esac
  log "$CLUSTER_NODE: done"
}

main "$@"
