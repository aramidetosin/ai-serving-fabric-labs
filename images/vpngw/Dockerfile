# check=skip=InvalidDefaultArgInFrom
# sfab/vpngw: the operator site's VPN router (chapter 4): strongSwan's charon with swanctl, on
# sfab/client (its network init and test tools), so the only packages this build adds are
# strongSwan and its one missing dependency, GMP, plus openssh-server (with its common files) and
# sudo for the admin login, each fetched from Alpine 3.20's own mirror and checked against the
# sha256 spec/versions.yaml pins before it is installed.
#
# Build with `make -C images vpngw` (images/vpngw/image.mk). PID 1 is tini running vpngw-run.sh;
# the topology runs /usr/local/sbin/sfab-init.sh as the node's exec once the links are attached:
# the client's network step, the admin SSH login (key only, listening on the management address
# only, with the keys the topology binds at /sfab/authorized_keys), then the tunnel from the bound
# bootstrap/<node>/swanctl.conf with the pre-shared key the topology binds at IPSEC_DIR
# (state/secrets/ipsec, read-only). The image holds no key, lab name or organization name; sshd's
# host keys are made in each container.

ARG CLIENT_BASE
FROM ${CLIENT_BASE}
ARG IMAGE_VERSION=1
ARG STRONGSWAN_VERSION
ARG STRONGSWAN_SHA256
ARG GMP_VERSION
ARG GMP_SHA256
ARG OPENSSH_VERSION
ARG OPENSSH_SHA256
ARG OPENSSH_COMMON_SHA256
ARG SUDO_VERSION
ARG SUDO_SHA256
LABEL org.opencontainers.image.title="sfab vpngw" \
      org.opencontainers.image.description="Lab VPN router: strongSwan (charon, swanctl) and sshd on the sfab test client" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
RUN set -eu; \
    for v in STRONGSWAN_VERSION STRONGSWAN_SHA256 GMP_VERSION GMP_SHA256 OPENSSH_VERSION OPENSSH_SHA256 \
             OPENSSH_COMMON_SHA256 SUDO_VERSION SUDO_SHA256; do \
      eval "[ -n \"\${$v:-}\" ]" || { echo "$v must be pinned in spec/versions.yaml" >&2; exit 1; }; \
    done; \
    mkdir -p /tmp/apk; cd /tmp/apk; \
    apk update >/dev/null; \
    apk fetch strongswan gmp openssh-server openssh-server-common sudo; \
    printf '%s  %s\n' "$STRONGSWAN_SHA256" "strongswan-${STRONGSWAN_VERSION}.apk" "$GMP_SHA256" "gmp-${GMP_VERSION}.apk" \
      "$OPENSSH_SHA256" "openssh-server-${OPENSSH_VERSION}.apk" \
      "$OPENSSH_COMMON_SHA256" "openssh-server-common-${OPENSSH_VERSION}.apk" \
      "$SUDO_SHA256" "sudo-${SUDO_VERSION}.apk" | sha256sum -c -; \
    apk verify ./*.apk; \
    apk add --no-network ./*.apk; \
    cd /; rm -rf /tmp/apk /var/cache/apk/*; \
    rm -f /etc/swanctl/conf.d/*.conf /etc/ssh/ssh_host_*; \
    apk info -v 2>/dev/null | LC_ALL=C sort > /usr/share/sfab-vpngw-packages.txt; \
    mkdir -p /etc/sfab /run/sfab
COPY vpngw-init.sh /usr/local/sbin/sfab-vpngw-init.sh
COPY vpngw-run.sh /usr/local/sbin/vpngw-run.sh
RUN set -eu; mv /usr/local/sbin/sfab-init.sh /usr/local/sbin/sfab-net-init.sh; \
    mv /usr/local/sbin/sfab-vpngw-init.sh /usr/local/sbin/sfab-init.sh; \
    chmod 0755 /usr/local/sbin/sfab-net-init.sh /usr/local/sbin/sfab-init.sh /usr/local/sbin/vpngw-run.sh
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD /usr/local/sbin/vpngw-run.sh --health >/dev/null || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/sbin/vpngw-run.sh"]
