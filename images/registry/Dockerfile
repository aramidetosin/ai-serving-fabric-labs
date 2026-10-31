# check=skip=InvalidDefaultArgInFrom
# sfab/registry: the in-lab registry (FRAMEWORK.md section 5). registry:2 (distribution 2.8.3),
# pinned by digest, plus the container init the clients use, so the topology can address it like
# any other container host. It serves HTTPS with the leaf certificate the topology binds at
# /sfab/tls (sfab-ca signs it on the lab host); the image holds no certificate or key.
#
# Build with `make -C images registry`: it passes the pinned base as REGISTRY_BASE and images/client
# as the named build context "client", whose init.sh becomes /usr/local/sbin/sfab-init.sh. PID 1 is
# the registry on config.yml (read-only, port 5000); the topology runs sfab-init.sh as the node's
# exec once the links attach, and binds images/registry/data read-only at /var/lib/registry.
# `make -C images registry-seed` runs the same image on seed.yml to fill that directory. The image
# holds no data, password, key, lab name or organization name.

ARG REGISTRY_BASE
FROM ${REGISTRY_BASE}
ARG IMAGE_VERSION=3
LABEL org.opencontainers.image.title="sfab registry" \
      org.opencontainers.image.description="Read-only registry mirror over HTTPS (distribution 2.8.3) with the sfab container init" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
RUN apk add --no-cache bash iproute2 ethtool
COPY config.yml /etc/docker/registry/config.yml
COPY seed.yml /etc/sfab/registry-seed.yml
COPY --from=client init.sh /usr/local/sbin/sfab-init.sh
RUN chmod 0755 /usr/local/sbin/sfab-init.sh
# The lab's registry listens with TLS (config.yml); the seeding registry (seed.yml) with plain HTTP
# on the loopback. Either way the port answers.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
  CMD nc -z 127.0.0.1 5000 || exit 1
EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/etc/docker/registry/config.yml"]
