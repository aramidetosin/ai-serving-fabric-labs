# check=skip=InvalidDefaultArgInFrom
# sfab/serving: the model server and its RPC workers (serving-layer/README.md), and nothing else.
#
#   base     debian:12-slim by digest (DEBIAN_BASE)
#   libs     libgomp1 and libssl3, the two Debian 12 packages the release's binaries need beyond the
#            base (libgomp.so.1, libssl.so.3, libcrypto.so.3), installed from the pinned .deb files
#   llama    llama.cpp release b11382's x64 Ubuntu build: llama-server, ggml-rpc-server and the
#            shared libraries beside them, in /opt/llama; every other program of the release is left out
#   probes   sfab-ready, the readiness probes of the worker and the server
#
# No model: the weights are 14 to 16 GB a file, so the image holds none. A lab binds the models
# directory into its GPU nodes and the recipe mounts it into each server at /models (read-only, a
# PersistentVolume per node); a cluster outside the labs gives the recipe its own models path.
#
# Build with `make -C images serving`: the inputs come from the vendor directory as the named
# build context "vendor" (make -C images serving-fetch puts them there and checks each sha256), and
# every sha256 is checked again here. The image holds no key, no lab name and no organization name;
# its user is 65532.

ARG DEBIAN_BASE
FROM ${DEBIAN_BASE} AS llama
ARG LLAMA_ASSET
ARG LLAMA_SHA256
COPY --from=vendor ${LLAMA_ASSET} /tmp/llama.tar.gz
RUN echo "${LLAMA_SHA256}  /tmp/llama.tar.gz" | sha256sum -c - \
 && mkdir /opt/llama && tar -xzf /tmp/llama.tar.gz -C /opt/llama --strip-components=1 \
 && find /opt/llama -maxdepth 1 -type f ! -name '*.so*' ! -name llama-server ! -name ggml-rpc-server ! -name LICENSE -delete \
 && test -x /opt/llama/llama-server && test -x /opt/llama/ggml-rpc-server

FROM ${DEBIAN_BASE}
ARG IMAGE_VERSION=b11382-2
ARG LIBGOMP1_DEB
ARG LIBGOMP1_SHA256
ARG LIBSSL3_DEB
ARG LIBSSL3_SHA256
LABEL org.opencontainers.image.title="sfab serving" \
      org.opencontainers.image.description="llama.cpp b11382 llama-server and ggml-rpc-server, no model" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.licenses="MIT"
RUN --mount=type=bind,from=vendor,source=debs,target=/tmp/debs \
    cd /tmp/debs && printf '%s  %s\n%s  %s\n' "${LIBGOMP1_SHA256}" "${LIBGOMP1_DEB}" "${LIBSSL3_SHA256}" "${LIBSSL3_DEB}" | sha256sum -c - \
 && dpkg -i "${LIBGOMP1_DEB}" "${LIBSSL3_DEB}"
RUN install -d -m 0755 /models
COPY --from=llama /opt/llama /opt/llama
COPY --chmod=0755 sfab-ready /usr/local/bin/sfab-ready
RUN ln -s /opt/llama/llama-server /usr/local/bin/llama-server \
 && ln -s /opt/llama/ggml-rpc-server /usr/local/bin/ggml-rpc-server \
 && LD_LIBRARY_PATH=/opt/llama ldd /opt/llama/llama-server /opt/llama/ggml-rpc-server | awk '/not found/ { bad = 1; print } END { exit bad }'
ENV LD_LIBRARY_PATH=/opt/llama
USER 65532:65532
WORKDIR /tmp
CMD ["llama-server", "--help"]
