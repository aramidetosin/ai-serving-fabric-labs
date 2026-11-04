# check=skip=InvalidDefaultArgInFrom
# sfab/client: the test client every population uses (the operator's client, the enterprise
# client, the internet client). Pinned Alpine plus the tools the audits, traces and drills run.
#
# Build with `make -C images client` (it passes the pinned base image as ALPINE_BASE). PID 1 is
# tini with an idle loop; the topology runs /usr/local/sbin/sfab-init.sh as its exec once the
# links are attached, and the script reads the bound bootstrap/<node>/init.env. The image holds
# no password, key, lab name or organization name.

ARG ALPINE_BASE
FROM ${ALPINE_BASE}
ARG IMAGE_VERSION=2
LABEL org.opencontainers.image.title="sfab client" \
      org.opencontainers.image.description="Test client: curl, openssl, dig, tcpdump, iperf3, python3, iproute2, ethtool, jq" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
RUN apk add --no-cache \
      bash ca-certificates curl openssl bind-tools tcpdump iperf3 python3 iproute2 ethtool jq \
      iputils openssh-client tini
COPY init.sh /usr/local/sbin/sfab-init.sh
RUN chmod 0755 /usr/local/sbin/sfab-init.sh
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/sh", "-c", "while :; do sleep 3600; done"]
