# check=skip=InvalidDefaultArgInFrom
# sfab/frr: the FRR router every build uses (build A's uplink and ISP routers, build B's carrier).
# FRR 10.5.4 from the project's own image on quay.io, pinned by digest, plus the tools the audits,
# traces and drills run on a router, baked in so nothing is fetched at boot.
#
# Build with `make -C images frr` (it passes the pinned base image as FRR_BASE). PID 1 is tini,
# which runs frr-init.sh; the script reads the bound bootstrap/<router>/init.env, puts eth0 in VRF
# mgmt, prepares the ports, links the rendered frr.conf, daemons and vtysh.conf into /etc/frr and
# hands over to FRR's own docker-start (watchfrr). `sfab-frr-restore check|restore` compares the
# running configuration with the render, or puts the render back. The image holds no password,
# key, lab name or organization name; sshd's host keys are made in each container.

ARG FRR_BASE
FROM ${FRR_BASE}
ARG IMAGE_VERSION=10.5.4-3
LABEL org.opencontainers.image.title="sfab frr" \
      org.opencontainers.image.description="FRR 10.5.4 router: VRF mgmt for eth0, sshd in that VRF, tcpdump, iproute2, ethtool" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
RUN apk add --no-cache openssh-server openssh-keygen tcpdump iproute2 ethtool sudo bash \
 && rm -f /etc/ssh/ssh_host_*
COPY frr-init.sh /usr/local/sbin/frr-init.sh
COPY frr-restore.sh /usr/local/sbin/sfab-frr-restore
RUN chmod 0755 /usr/local/sbin/frr-init.sh /usr/local/sbin/sfab-frr-restore
HEALTHCHECK --interval=10s --timeout=5s --start-period=240s --retries=3 \
  CMD vtysh -c 'show version' >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/sbin/frr-init.sh"]
CMD ["/usr/lib/frr/docker-start"]
