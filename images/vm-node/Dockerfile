# check=skip=InvalidDefaultArgInFrom
# sfab/vm-node: a KVM Ubuntu 24.04 guest wrapped in a container, so containerlab wires it like
# any other node. vm-init.sh (PID 1) bridges each container NIC to a tap, builds the guest's
# NoCloud seed from the bound bootstrap/<node>/node.env, and boots the guest on a qcow2 overlay
# of the baked base disk.
#
# Build with `make -C images vm-node` (it passes the pinned base image as UBUNTU_BASE and the
# archive snapshot as UBUNTU_SNAPSHOT). BuildKit is required. Two targets:
#   runtime  QEMU and the tools, used by `make -C images vm-node-base` to bake the base disk
#   node     runtime plus the baked base disk at /base/node.qcow2 and the node scripts; the disk
#            comes from the named build context "base" (--build-context base=<bake directory>)
# The image holds no password, key, lab name or organization name: those reach the guest
# through node.env and the bound authorized_keys file.

ARG UBUNTU_BASE
FROM ${UBUNTU_BASE} AS runtime
ARG UBUNTU_SNAPSHOT
ENV DEBIAN_FRONTEND=noninteractive
# The packages come from the Ubuntu archive as snapshot.ubuntu.com served it at UBUNTU_SNAPSHOT,
# so the same pins give the same packages. The snapshot service is reached over HTTPS, which needs
# ca-certificates first: only that package (with openssl) comes from the base image's own sources.
# The snapshot service answers 5xx now and then, so every download retries. The base image's
# sources are put back at the end, and the package list is kept in the image.
RUN set -eu; \
    retry() { n=1; until "$@"; do [ "$n" -ge 8 ] && return 1; echo "retry $n: $*" >&2; sleep $((n * 10)); n=$((n + 1)); done; }; \
    apt_get() { apt-get -q -o Acquire::Retries=10 -o APT::Update::Error-Mode=any "$@"; }; \
    pkgs="qemu-system-x86 qemu-utils cloud-image-utils genisoimage iproute2 ethtool gettext-base socat ca-certificates curl procps iputils-ping"; \
    src=/etc/apt/sources.list.d/ubuntu.sources; \
    cp "$src" /tmp/ubuntu.sources.base; \
    if [ -n "${UBUNTU_SNAPSHOT:-}" ]; then \
      retry apt_get update; \
      apt_get install -y --no-install-recommends ca-certificates; \
      rm -rf /var/lib/apt/lists/*; \
      sed -i -E "s#^URIs:.*#URIs: https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#" "$src"; \
    fi; \
    retry apt_get update; \
    retry apt_get install -y --no-install-recommends --download-only $pkgs; \
    apt_get install -y --no-install-recommends $pkgs; \
    mv /tmp/ubuntu.sources.base "$src"; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    dpkg-query -W -f='${Package} ${Version}\n' | LC_ALL=C sort > /usr/share/sfab-runtime-packages.txt

FROM runtime AS node
ARG IMAGE_VERSION=2
LABEL org.opencontainers.image.title="sfab vm-node" \
      org.opencontainers.image.description="KVM Ubuntu 24.04 guest for containerlab, with containerd and kubeadm baked into its base disk" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
# The base disk first: it is the large layer, and it changes only when it is baked again. The copy
# sets its mode, since a later chmod would store the whole disk a second time.
COPY --from=base --chmod=0444 node.qcow2 node.id /base/
COPY --chmod=0755 vm-init.sh /usr/local/bin/vm-init.sh
COPY node-files/ /opt/sfab/node-files/
RUN chmod 0755 /opt/sfab/node-files/*.sh
ENTRYPOINT ["/usr/local/bin/vm-init.sh"]
