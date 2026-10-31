# check=skip=InvalidDefaultArgInFrom
# sfab/keys: the API key tool (images/keys/README.md): sfab-keys, which makes keys inside the
# cluster and never prints one, composes the API gateway's consumers from a mounted Secret, and
# probes which gateway pods have loaded a key.
#
# Built with `make -C images keys` on sfab/client (CLIENT_IMAGE: pinned Alpine with Python 3.12),
# so it needs no package download of its own; the one library beyond Python's standard library is
# PyYAML from its pinned wheel (CPython 3.12, musl), which make -C images keys-fetch puts in the
# vendor directory, the named build context "vendor", and whose sha256 is checked again here. The
# wheel is unpacked into site-packages with Python's zipfile, without pip and without an index.
# The image holds no key, no lab name and no organization name; its user is 65532.

ARG CLIENT_IMAGE
FROM ${CLIENT_IMAGE}
ARG IMAGE_VERSION=1
ARG PYYAML_WHEEL
ARG PYYAML_SHA256
ARG PYYAML_VERSION
LABEL org.opencontainers.image.title="sfab keys" \
      org.opencontainers.image.description="API key tool: in-cluster keys, the API gateway's consumers, per-pod key probes" \
      org.opencontainers.image.version="${IMAGE_VERSION}"
COPY --from=vendor ${PYYAML_WHEEL} /tmp/
RUN echo "${PYYAML_SHA256}  /tmp/${PYYAML_WHEEL}" | sha256sum -c - \
 && site="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["platlib"])')" \
 && python3 -m zipfile -e "/tmp/${PYYAML_WHEEL}" "$site" && rm -f "/tmp/${PYYAML_WHEEL}" \
 && python3 -c "import yaml, sys; sys.exit(0 if yaml.__version__ == '${PYYAML_VERSION}' else 1)"
COPY sfab-keys /usr/local/bin/sfab-keys
RUN chmod 0755 /usr/local/bin/sfab-keys && sfab-keys --help >/dev/null
USER 65532:65532
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sfab-keys", "--help"]
