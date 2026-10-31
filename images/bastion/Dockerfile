# check=skip=InvalidDefaultArgInFrom
# sfab/bastion: the operator's jump host inside the lab (FRAMEWORK.md section 5):
# sshd with key-only login, lldpd, and the operator's tools (kubectl, helm and cilium-cli at their
# pinned versions, dig, openssl, curl). It serves nothing: no DNS, no time and no CA (the services
# hosts and the lab host hold those), and it holds no standing cluster-admin kubeconfig.
#
# Build with `make -C images bastion` (images/bastion/image.mk): it passes the pinned base image
# as UBUNTU_BASE, the archive snapshot as UBUNTU_SNAPSHOT, and each tool's version and sha256 from
# spec/versions.yaml. A download whose sha256 differs from its pin stops the build. PID 1 is
# bastion-init.sh, which reads the bound bootstrap/<bastion>/init.env. The image holds no password,
# key, lab name or organization name: sshd's host keys are made in each container, and the
# package-made ones are removed here.

ARG UBUNTU_BASE
FROM ${UBUNTU_BASE}
ARG UBUNTU_SNAPSHOT
ARG IMAGE_VERSION=4
ARG KUBECTL_VERSION
ARG KUBECTL_SHA256
ARG HELM_VERSION
ARG HELM_SHA256
ARG CILIUM_CLI_VERSION
ARG CILIUM_CLI_SHA256
ENV DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.title="sfab bastion" \
      org.opencontainers.image.description="Lab jump host: sshd, lldpd, kubectl, helm, cilium-cli" \
      org.opencontainers.image.version="${IMAGE_VERSION}"

# The packages come from the Ubuntu archive as snapshot.ubuntu.com served it at UBUNTU_SNAPSHOT,
# so the same pins give the same packages. The snapshot service is reached over HTTPS, which needs
# ca-certificates first: only that package (with openssl) comes from the base image's own sources.
# The snapshot service answers 5xx now and then, so every download retries. The base image's
# sources are put back at the end, and the package list is kept in the image.
RUN set -eu; \
    retry() { n=1; until "$@"; do [ "$n" -ge 8 ] && return 1; echo "retry $n: $*" >&2; sleep $((n * 10)); n=$((n + 1)); done; }; \
    apt_get() { apt-get -q -o Acquire::Retries=10 -o APT::Update::Error-Mode=any "$@"; }; \
    pkgs="bind9-dnsutils openssh-server lldpd jq openssl ca-certificates curl \
          iproute2 ethtool procps iputils-ping sudo bash-completion netcat-openbsd tcpdump less"; \
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
    dpkg-query -W -f='${Package} ${Version}\n' | LC_ALL=C sort > /usr/share/sfab-bastion-packages.txt

# kubectl, helm and cilium-cli, each checked against its pinned sha256 before it is installed.
RUN set -eu; \
    for v in KUBECTL_VERSION KUBECTL_SHA256 HELM_VERSION HELM_SHA256 CILIUM_CLI_VERSION CILIUM_CLI_SHA256; do \
      eval "x=\${$v:-}"; [ -n "$x" ] || { echo "build argument $v is empty: pin it in spec/versions.yaml" >&2; exit 1; }; \
    done; \
    get() { curl -fsSL --retry 5 --retry-delay 10 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    cd /tmp; \
    get kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256"; \
    install -m 0755 kubectl /usr/local/bin/kubectl; \
    get helm.tar.gz "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" "$HELM_SHA256"; \
    tar -xzf helm.tar.gz linux-amd64/helm; \
    install -m 0755 linux-amd64/helm /usr/local/bin/helm; \
    get cilium.tar.gz "https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz" "$CILIUM_CLI_SHA256"; \
    tar -xzf cilium.tar.gz cilium; \
    install -m 0755 cilium /usr/local/bin/cilium; \
    rm -rf /tmp/kubectl /tmp/helm.tar.gz /tmp/linux-amd64 /tmp/cilium.tar.gz /tmp/cilium; \
    printf 'kubectl %s\nhelm %s\ncilium-cli %s\n' "$KUBECTL_VERSION" "$HELM_VERSION" "$CILIUM_CLI_VERSION" > /usr/share/sfab-bastion-tools.txt

# No key the packages made stays in the image (each container makes its own), and no service
# starts from the packages' own configuration. The base image's stock user goes too, so the
# operator user bastion-init.sh makes is the only login.
RUN rm -f /etc/ssh/ssh_host_* \
 && if id -u ubuntu >/dev/null 2>&1; then userdel -r ubuntu 2>/dev/null || userdel ubuntu; fi \
 && mkdir -p /etc/sfab /workspace /run/sfab

COPY bastion-init.sh /usr/local/sbin/bastion-init.sh
COPY operator-shell.sh /etc/profile.d/sfab-operator.sh
RUN chmod 0755 /usr/local/sbin/bastion-init.sh \
 && chmod 0644 /etc/profile.d/sfab-operator.sh \
 && printf '\n# the operator environment (images/bastion/operator-shell.sh)\n[ -r /etc/profile.d/sfab-operator.sh ] && . /etc/profile.d/sfab-operator.sh\n' >> /etc/bash.bashrc

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=3 \
  CMD /usr/local/sbin/bastion-init.sh --health >/dev/null || exit 1
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/bastion-init.sh"]
