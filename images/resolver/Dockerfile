# check=skip=InvalidDefaultArgInFrom
# sfab/resolver: the lab's DNS and time servers (FRAMEWORK.md section 5): the
# platform's authoritative pair (BIND, ROLE bind-auth), its two recursive resolvers (BIND, ROLE
# bind-recursive, with chrony serving time), the enterprise's corporate resolver (dnsmasq, ROLE
# dnsmasq), the operator's and the internet's public servers (bind-auth) and the upstream time
# reference (chrony alone, with NTS). Pinned Alpine with BIND, dnsmasq and chrony at the package
# versions spec/versions.yaml pins, so the behavior the chapters record is the pinned releases'.
#
# Build with `make -C images resolver` (images/resolver/image.mk): it passes the pinned base image
# as ALPINE_BASE, the package pins, and images/client as the named build context "client" (its
# init.sh is the network step, /usr/local/sbin/sfab-net-init.sh). PID 1 is tini running
# resolver-run.sh; the topology runs /usr/local/sbin/sfab-init.sh as the node's exec once the links
# are attached, and the script reads the bound bootstrap/<node>/ (init.env, named.conf and zones/,
# or dnsmasq.conf, and chrony.conf). The image holds no password, key, lab name or organization
# name; the rndc key is made in each container, the TSIG keys and the NTS key are bound per lab.

ARG ALPINE_BASE
FROM ${ALPINE_BASE}
ARG IMAGE_VERSION=3
ARG BIND_VERSION
ARG DNSMASQ_VERSION
ARG CHRONY_VERSION
LABEL org.opencontainers.image.title="sfab resolver" \
      org.opencontainers.image.description="Lab DNS and time server: BIND (authoritative or recursive), dnsmasq or chrony, with the sfab container init" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
RUN set -eu; \
    [ -n "${BIND_VERSION:-}" ] && [ -n "${DNSMASQ_VERSION:-}" ] && [ -n "${CHRONY_VERSION:-}" ] || \
      { echo "BIND_VERSION, DNSMASQ_VERSION and CHRONY_VERSION must be pinned in spec/versions.yaml" >&2; exit 1; }; \
    apk add --no-cache "bind=${BIND_VERSION}" "bind-tools=${BIND_VERSION}" "dnsmasq=${DNSMASQ_VERSION}" "chrony=${CHRONY_VERSION}" \
      bash ca-certificates iproute2 ethtool iputils tini; \
    rm -f /etc/bind/rndc.key /etc/chrony/chrony.keys; \
    apk info -v 2>/dev/null | LC_ALL=C sort > /usr/share/sfab-resolver-packages.txt; \
    mkdir -p /etc/sfab /run/sfab /var/cache/bind /var/log/named /var/lib/chrony
COPY --from=client init.sh /usr/local/sbin/sfab-net-init.sh
COPY sfab-dns sfab-ntp /usr/local/bin/
COPY resolver-init.sh /usr/local/sbin/sfab-init.sh
COPY resolver-run.sh /usr/local/sbin/resolver-run.sh
RUN chmod 0755 /usr/local/sbin/sfab-net-init.sh /usr/local/bin/sfab-dns /usr/local/bin/sfab-ntp /usr/local/sbin/sfab-init.sh \
      /usr/local/sbin/resolver-run.sh
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD /usr/local/sbin/resolver-run.sh --health >/dev/null || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/sbin/resolver-run.sh"]
