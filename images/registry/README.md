# sfab/registry

The lab's own registry: every image a node pulls and every chart `finish` installs, served inside the lab so a lab runs offline. It is `registry:2` (distribution 2.8.3), pinned by digest in `spec/versions.yaml` (`images.registry_upstream`), with the container init the clients use (`images/client/init.sh`) added as `/usr/local/sbin/sfab-init.sh`.

```
make -C images registry          # sfab/registry:3
make -C images registry-plan     # what the seed copies, from spec/versions.yaml
make -C images registry-seed     # copy it into the registry's data (needs the internet, once)
make -C images registry-check    # the data holds every pin (offline)
make -C images registry-link     # point images/registry/data at the data again
```

## Where it sits

The registry is on the operator side, on its own /30 behind the uplink router (192.0.2.6 in build A). A node's pull leaves the data VLAN through the firewall's source NAT, so the registry's access log shows the firewall's public address, never a node's own. The topology binds the data read-only at `/var/lib/registry` and runs `sfab-init.sh` as the node's exec once the links are attached; PID 1 is the registry on `config.yml`: HTTPS on port 5000 with a leaf of the lab's internet intermediate (`registry.upstream.example` and its address, signed on the lab host by `common/ca/sfab-ca` into `state/tls/registry/`, bound read-only at `/sfab/tls`), read-only, delete off. A push is refused with HTTP 405. The seeding registry (`registry-seed`) runs the same image on the lab host's loopback with its own configuration, plain HTTP and writable.

## The mirror's layout

| Upstream | Served as |
|---|---|
| image `<host>/<repo>:<tag>` pinned by digest | `<mirror>/<host>/<repo>:<tag>`, for example `192.0.2.6:5000/registry.k8s.io/sig-storage/csi-attacher:v4.4.0` |
| chart `<name>` `<version>` pinned by the sha256 of its `.tgz` | the OCI artifact `<mirror>/charts/<name>:<version>`, installed with `helm upgrade --install ... oci://<mirror>/charts/<name> --version <version> --ca-file /shared/ca/root.crt` |
| an image built here, `sfab/<name>:<tag>` (`mirror: local`) | `<mirror>/sfab/<name>:<tag>`, for example `192.0.2.6:5000/sfab/serving:b11382-2`, which a pod names that way |

Every node gets one containerd `hosts.toml` per upstream host, in the one `config_path` directory `/etc/containerd/certs.d/<host>/hosts.toml`. `override_path = true` makes the mirror URL's path the API root, so a pull of `registry.k8s.io/pause:3.10.1` asks `https://192.0.2.6:5000/v2/registry.k8s.io/pause/manifests/3.10.1`, verified against the lab root:

```
server = "https://registry.k8s.io"

[host."https://192.0.2.6:5000/v2/registry.k8s.io"]
  capabilities = ["pull", "resolve"]
  override_path = true
  ca = "/shared/ca/root.crt"
```

`seed.py hosts-toml --mirror <address:port> --scheme https --ca /shared/ca/root.crt <host>` prints that file. A pod names an image built here by the mirror's own address, so a lab that runs the serving recipe gives every node one more file, `/etc/containerd/certs.d/<mirror>/hosts.toml`, whose server is the mirror itself over HTTPS (`seed.py hosts-toml --mirror <address:port> --scheme https --ca /shared/ca/root.crt --local` prints it). When the mirror misses, containerd falls back to the upstream server, which an offline lab cannot reach, so the pull fails inside the lab rather than leaving it.

## What the seed copies

Every image pin with a registry host, a tag and a digest under `kubernetes:` (an add-on's `images:` or `image:`), under `mirror.images`, or under `images:` with `mirror: true`; every chart under `kubernetes:` (an add-on's `chart:`) and under `mirror.charts`. An entry with `used: false` is left out.

- **Every platform.** An image is copied with every platform its pinned index lists, digests kept (`skopeo copy --all --preserve-digests`), so a pull by tag and a pull by the pinned digest both resolve.
- **One platform from Docker Hub.** Each manifest request to docker.io counts against Docker Hub's anonymous pull limit, which the lab host shares, and an official image's index lists about twenty manifests with its attestations. From docker.io the seed reads the pinned index once, checks its sha256 against the pin, and copies only the linux/amd64 manifest it names: two manifest requests per image. The mirror serves that manifest under the tag, and `SEED.json` records its digest beside the pinned one. Reference such an image by its tag (or the recorded platform digest), never by its index digest. A pin may say `platforms: all` or `platforms: one` to choose for itself.
- **Charts** are downloaded once into `vendor/charts/` (the repository's direct URL, else its `index.yaml`), checked against their sha256, and pushed through the registry's HTTP API with the OCI layout helm writes.

The seed runs a seeding registry from this image on `seed.yml` on the host's loopback (`--network host`, `127.0.0.1:5099`), so no port is published and no firewall rule is touched, and each skopeo copy on the host network too. Its containers are named after `SEED_NAME` (`sfab-registry-seed`, and `sfab-registry-seed-copy` for the copies) and removed when it ends. Every copy is read back from the registry and must carry the expected digest. A second run finds everything present and makes no upstream request. `SEED.json` at the top of the data directory records what was copied.

## The images built here

Two pins under `images:` say `mirror: local`: `sfab/serving` and `sfab/keys`, which this repository builds on the lab host and the cluster pulls. They carry no digest, since the build makes them. After the upstream copies, the seed pushes each from the host's Docker: `docker save` into a work directory (`SEED_WORK`, `VENDOR_DIR/tmp` by default, removed after each push), then every blob through the registry's HTTP API, the layers uncompressed as Docker saved them, and an OCI manifest written from the saved config and layers, so the same image always gives the same manifest digest. `SEED.json` records each image's Docker id and the manifest served; a later seed whose image id and served manifest still match pushes nothing, and a rebuilt image is pushed again. `registry-seed` builds both images first when they are missing or stale (`make -C images serving keys`), and `registry-check` wants each one's tag on the manifest `SEED.json` records, with every blob it names.

## The data directory

The data lives in `images/registry/data`, which git ignores. With `SFAB_IMAGE_STORE=<dir>` it lives in `<dir>/registry-data` and `images/registry/data` is a link to it. A checkout kept in step with `rsync --delete` must exclude `images/registry/data`, or the sync removes the link; `make -C images registry-link` puts it back, and `registry-check` fails while the link is missing.
