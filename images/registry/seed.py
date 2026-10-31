#!/usr/bin/env python3
"""Fill the in-lab registry's data directory from spec/versions.yaml (FRAMEWORK.md section 5).

    seed.py plan                                print every image and chart the labs pull
    seed.py run --data DIR --image IMAGE ...    copy them into DIR through a seeding registry
    seed.py check --data DIR                    verify DIR holds every pin, offline
    seed.py hosts-toml --mirror ADDR UPSTREAM   the containerd hosts.toml a node needs for UPSTREAM

What is seeded. Every image pin with a ref and a digest under `kubernetes:` (an add-on's
`images:` mapping, or its one `image:`), every entry of `mirror.images`, and every `images:`
entry marked `mirror: true`; every chart under `kubernetes:` (an add-on's `chart:`) and in
`mirror.charts`. An entry with `used: false` is left out. A ref names its registry host
(registry.k8s.io/pause:3.10.1, docker.io/library/busybox:1.37.0) and its tag; the digest is
separate. The same ref pinned twice with two digests is an error.

Where it goes. An image <host>/<repo>:<tag> is copied by digest to <mirror>/<host>/<repo>:<tag>,
so a pull by tag and a pull by the pinned digest both resolve. A node's containerd reaches it
through /etc/containerd/certs.d/<host>/hosts.toml with override_path = true (hosts_toml() below).
A chart <name> <version> is pushed as an OCI artifact to <mirror>/charts/<name>:<version>, which
helm installs as oci://<mirror>/charts/<name> --version <version> (with --ca-file and the lab root
when the lab's registry serves HTTPS; the seeding registry itself is plain HTTP on the loopback).

Every platform, or one. An image is copied with every platform its pinned index lists
(`copy --all`), except from the hosts in ONE_PLATFORM_HOSTS (docker.io): every manifest request
there counts against Docker Hub's anonymous pull limit, which the lab host shares, and an index
with its attestations lists twenty manifests. From those hosts the seed reads the pinned index
once, checks its sha256 against the pin, and copies only the linux/amd64 manifest the index names
(PLATFORM), so the whole image costs two manifest requests. The mirror then serves that manifest
under the tag, and SEED.json records its digest beside the pinned one: a node pulls such an image
by tag (or by the recorded platform digest), never by the index digest. A pin may say
`platforms: all` to copy every platform from any host, or `platforms: one` to copy one from any.

How. `run` starts the registry image on seed.yml with the data directory bound read-write, on the
lab host's loopback (--network host, REGISTRY_HTTP_ADDR=127.0.0.1:<port>), so no port is
published and no firewall rule is touched. Each image is copied by skopeo (`copy
--preserve-digests`, run from the pinned skopeo image, also on the host network) unless the
registry already holds it under that tag, so a second run pulls nothing. Every container the seed
starts is named after --name (the registry itself, and <name>-copy for each skopeo run). Each
chart is downloaded once into <vendor>/charts/<name>-<version>.tgz, checked against its sha256,
and pushed with the registry's HTTP API. Every copy is read back and must carry the expected
digest. `run` then writes SEED.json at the top of the data directory and removes the seeding
registry. The lab's registry serves the directory read-only (config.yml). `check` reads the
data directory offline, with SEED.json for the one-platform images.

Images built here. An `images:` entry marked `mirror: local` names an image this repository
builds on the lab host (sfab/serving, sfab/keys): its ref has no registry host and no digest is
pinned for it, since the build makes it. `run` pushes it from the host's Docker after the
upstream copies: `docker save` into a work directory (--work, default <vendor>/tmp), then every
blob through the registry's HTTP API, the layers uncompressed as Docker saved them, and an OCI
manifest written from the saved config and layers, byte-stable, so the same image always gives
the same manifest digest. It is served as <mirror>/<repo>:<tag> (192.0.2.6:5000/sfab/serving:...
in build A), which a node pulls through the hosts.toml for the mirror itself (hosts_toml_local()).
SEED.json records the image's Docker id and the manifest digest served; a later run whose id and
served manifest still match pushes nothing.

Standard library only. versions.yaml is read with images/versions.py (PyYAML when installed).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGES = HERE.parent
ROOT = IMAGES.parent
sys.path.insert(0, str(IMAGES))
import versions as pins  # noqa: E402  (images/versions.py)

CHARTS_PATH = "charts"
SEED_FILE = "SEED.json"
SCHEMA = 1
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# A repository path component, as distribution accepts it.
COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")

# Where containerd sends a host's pulls when the mirror fails; docker.io's API lives elsewhere.
UPSTREAM_SERVER = {"docker.io": "https://registry-1.docker.io"}
# Hosts whose images are copied for one platform only (see the module docstring), and that
# platform: the lab host and every guest are x86_64.
ONE_PLATFORM_HOSTS = ("docker.io",)
PLATFORM = {"os": "linux", "architecture": "amd64"}
PLATFORM_NAME = "linux/amd64"
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")

MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TAR = "application/vnd.oci.image.layer.v1.tar"
HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"
HELM_LAYER = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
# The Chart.yaml fields copied into the OCI config, as helm push writes them.
CHART_FIELDS = ("apiVersion", "name", "version", "kubeVersion", "description", "type", "appVersion", "home", "icon")


class SeedError(Exception):
    pass


def log(msg: str) -> None:
    print(f"[seed] {msg}", flush=True)


# ------------------------------------------------------------------------------------------
# The pins


@dataclass(frozen=True)
class Image:
    id: str            # where it is pinned: kubernetes.democratic_csi.images.driver
    host: str          # registry.k8s.io
    repo: str          # pause, library/busybox
    tag: str
    digest: str
    platform: str | None = None   # PLATFORM_NAME when only that platform is copied

    @property
    def ref(self) -> str:
        return f"{self.host}/{self.repo}:{self.tag}"

    @property
    def source(self) -> str:
        return f"{self.host}/{self.repo}@{self.digest}"

    @property
    def mirror_repo(self) -> str:
        return f"{self.host}/{self.repo}"

    @property
    def mirror_path(self) -> str:
        return f"{self.host}/{self.repo}:{self.tag}"


@dataclass(frozen=True)
class Chart:
    id: str
    name: str
    version: str
    sha256: str
    repo: str | None = None
    url: str | None = None

    @property
    def file(self) -> str:
        return f"{self.name}-{self.version}.tgz"

    @property
    def tag(self) -> str:
        """The OCI tag: the version with + written _, as helm push writes it."""
        return self.version.replace("+", "_")

    @property
    def mirror_repo(self) -> str:
        return f"{CHARTS_PATH}/{self.name}"

    @property
    def mirror_path(self) -> str:
        return f"{CHARTS_PATH}/{self.name}:{self.tag}"


def parse_ref(ref: str, where: str) -> tuple[str, str, str]:
    """(host, repo, tag) of '<host>/<repo>:<tag>'. docker.io one-word repos get library/."""
    ref = str(ref).strip()
    if "@" in ref:
        raise SeedError(f"{where}: ref {ref!r} carries a digest; give it as digest: instead")
    first, sep, rest = ref.partition("/")
    if not sep or not ("." in first or ":" in first or first == "localhost"):
        raise SeedError(f"{where}: ref {ref!r} must name its registry host, for example docker.io/library/busybox:1.37.0")
    repo, sep, tag = rest.rpartition(":")
    if not sep or "/" in tag:
        raise SeedError(f"{where}: ref {ref!r} has no tag")
    host = first.lower()
    if host in ("index.docker.io", "registry-1.docker.io"):
        host = "docker.io"
    if host == "docker.io" and "/" not in repo:
        repo = f"library/{repo}"
    for c in [host] + repo.split("/"):
        if c != host and not COMPONENT_RE.match(c):
            raise SeedError(f"{where}: ref {ref!r}: {c!r} is not a valid repository name component")
    if not TAG_RE.match(tag):
        raise SeedError(f"{where}: ref {ref!r}: {tag!r} is not a valid tag")
    return host, repo, tag


def _image(where: str, d: dict) -> Image | None:
    if d.get("used") is False:
        return None
    ref, digest = d.get("ref"), d.get("digest")
    if not ref:
        return None
    if not digest:
        raise SeedError(f"{where}: {ref} has no digest; pin it in spec/versions.yaml")
    digest = str(digest)
    if not DIGEST_RE.match(digest):
        raise SeedError(f"{where}: digest {digest!r} is not sha256:<64 hex>")
    host, repo, tag = parse_ref(str(ref), where)
    mode = d.get("platforms")
    if mode not in (None, "all", "one"):
        raise SeedError(f"{where}: platforms is all or one, not {mode!r}")
    one = mode == "one" or (mode is None and host in ONE_PLATFORM_HOSTS)
    return Image(id=where, host=host, repo=repo, tag=tag, digest=digest, platform=PLATFORM_NAME if one else None)


def _chart(where: str, d: dict) -> Chart | None:
    if d.get("used") is False or not d.get("version"):
        return None
    name = d.get("name")
    sha = str(d.get("sha256") or "")
    if not name:
        raise SeedError(f"{where}: a chart needs a name")
    if not SHA_RE.match(sha):
        raise SeedError(f"{where}: chart {name} {d.get('version')} needs the sha256 of its .tgz")
    if not d.get("repo") and not d.get("url"):
        raise SeedError(f"{where}: chart {name} needs a repo or a url")
    if not COMPONENT_RE.match(str(name)):
        raise SeedError(f"{where}: chart name {name!r} is not a valid repository name component")
    version = str(d["version"])
    if not TAG_RE.match(version.replace("+", "_")):
        raise SeedError(f"{where}: chart version {version!r} is not a valid tag")
    return Chart(id=where, name=str(name), version=version, sha256=sha,
                 repo=str(d["repo"]).rstrip("/") if d.get("repo") else None, url=str(d["url"]) if d.get("url") else None)


def collect(tree: dict) -> tuple[list[Image], list[Chart]]:
    """Every image and chart the labs pull, from the versions tree, sorted by mirror path."""
    found_i: list[Image] = []
    found_c: list[Chart] = []
    k8s = tree.get("kubernetes") or {}
    for addon, v in k8s.items():
        if not isinstance(v, dict):
            continue
        imgs = v.get("images")
        if isinstance(imgs, dict):
            for key, d in imgs.items():
                if isinstance(d, dict):
                    found_i.append(_image(f"kubernetes.{addon}.images.{key}", d))
        if isinstance(v.get("image"), dict):
            found_i.append(_image(f"kubernetes.{addon}.image", v["image"]))
        if isinstance(v.get("chart"), dict):
            found_c.append(_chart(f"kubernetes.{addon}.chart", v["chart"]))
    mirror = tree.get("mirror") or {}
    for key, d in (mirror.get("images") or {}).items():
        if isinstance(d, dict):
            found_i.append(_image(f"mirror.images.{key}", d))
    for key, d in (mirror.get("charts") or {}).items():
        if isinstance(d, dict):
            found_c.append(_chart(f"mirror.charts.{key}", d))
    for key, d in (tree.get("images") or {}).items():
        if isinstance(d, dict) and d.get("mirror") is True:
            found_i.append(_image(f"images.{key}", d))

    images: dict[str, Image] = {}
    for im in found_i:
        if im is None:
            continue
        have = images.get(im.ref)
        if have is not None and have.digest != im.digest:
            raise SeedError(f"{im.ref} is pinned twice with two digests: {have.id} {have.digest}, {im.id} {im.digest}")
        if have is not None and have.platform != im.platform:
            raise SeedError(f"{im.ref} is pinned twice with two platforms settings: {have.id}, {im.id}")
        images.setdefault(im.ref, im)
    charts: dict[tuple, Chart] = {}
    for c in found_c:
        if c is None:
            continue
        have = charts.get((c.name, c.version))
        if have is not None and have.sha256 != c.sha256:
            raise SeedError(f"chart {c.name} {c.version} is pinned twice with two sha256: {have.id}, {c.id}")
        charts.setdefault((c.name, c.version), c)
    return (sorted(images.values(), key=lambda x: x.mirror_path),
            sorted(charts.values(), key=lambda x: x.mirror_path))


@dataclass(frozen=True)
class Local:
    """An image this repository builds on the lab host (an images: entry with mirror: local)."""
    id: str            # images.serving
    ref: str           # sfab/serving:b11382-q05-1, its name in the host's Docker
    repo: str          # sfab/serving
    tag: str

    @property
    def mirror_repo(self) -> str:
        return self.repo

    @property
    def mirror_path(self) -> str:
        return f"{self.repo}:{self.tag}"


def collect_local(tree: dict) -> list[Local]:
    """The images built here that the mirror serves, sorted by mirror path."""
    out = []
    for key, d in (tree.get("images") or {}).items():
        if not isinstance(d, dict) or d.get("mirror") != "local":
            continue
        where = f"images.{key}"
        ref = str(d.get("ref") or "").strip()
        repo, sep, tag = ref.rpartition(":")
        if not ref or not sep or not repo or "/" in tag:
            raise SeedError(f"{where}: ref {ref!r} must be <repository>:<tag>")
        first = repo.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            raise SeedError(f"{where}: ref {ref!r} names a registry host; an image built here has none")
        for c in repo.split("/"):
            if not COMPONENT_RE.match(c):
                raise SeedError(f"{where}: ref {ref!r}: {c!r} is not a valid repository name component")
        if not TAG_RE.match(tag):
            raise SeedError(f"{where}: ref {ref!r}: {tag!r} is not a valid tag")
        if d.get("digest"):
            raise SeedError(f"{where}: an image built here has no pinned digest")
        out.append(Local(id=where, ref=ref, repo=repo, tag=tag))
    return sorted(out, key=lambda x: x.mirror_path)


def upstreams(images) -> list[str]:
    """The registry hosts the images come from: one hosts.toml per host on every node."""
    return sorted({im.host for im in images})


def hosts_toml(upstream: str, mirror: str, scheme: str = "http", ca: str | None = None) -> str:
    """The containerd hosts.toml for one upstream registry host (in certs.d/<upstream>/).

    override_path = true makes the host URL's path the API root, so a pull of
    <upstream>/<repo>:<tag> asks the mirror for /v2/<upstream>/<repo>/manifests/<tag>, which is
    where `run` copied it. When the mirror fails, containerd falls back to the upstream server,
    which an offline lab cannot reach: the pull fails rather than leaving the lab. A mirror that
    serves HTTPS is verified against ca (the lab root, as the guests mount it).
    """
    server = UPSTREAM_SERVER.get(upstream, f"https://{upstream}")
    return (f'server = "{server}"\n\n'
            f'[host."{scheme}://{mirror}/v2/{upstream}"]\n'
            f'  capabilities = ["pull", "resolve"]\n'
            f'  override_path = true\n' + (f'  ca = "{ca}"\n' if ca else ""))


def hosts_toml_local(mirror: str, scheme: str = "http", ca: str | None = None) -> str:
    """The containerd hosts.toml (in certs.d/<mirror>/) for the images built here, which a pod
    names as <mirror>/<repo>:<tag>: the mirror is the server itself."""
    return (f'server = "{scheme}://{mirror}"\n\n'
            f'[host."{scheme}://{mirror}"]\n'
            f'  capabilities = ["pull", "resolve"]\n' + (f'  ca = "{ca}"\n' if ca else ""))


# ------------------------------------------------------------------------------------------
# The registry HTTP API (the seeding registry: plain HTTP, no auth)


class Http:
    """A tiny client for one registry. opener(Request) returns a response object with
    .status, .headers and .read(), or raises urllib.error.HTTPError; tests pass their own."""

    def __init__(self, base: str, opener=None):
        self.base = base.rstrip("/")
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=120))

    def call(self, method: str, path: str, data: bytes | None = None, headers: dict | None = None):
        url = path if path.startswith("http") else self.base + path
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        try:
            r = self.opener(req)
            return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read() if hasattr(e, "read") else b""

    def ping(self) -> bool:
        try:
            st, _, _ = self.call("GET", "/v2/")
        except (OSError, urllib.error.URLError):
            return False
        return st == 200

    def manifest_digest(self, repo: str, ref: str) -> str | None:
        st, h, _ = self.call("HEAD", f"/v2/{repo}/manifests/{ref}", headers={"Accept": ", ".join(MANIFEST_TYPES)})
        if st != 200:
            return None
        return h.get("Docker-Content-Digest")

    def manifest(self, repo: str, ref: str) -> dict | None:
        st, _, body = self.call("GET", f"/v2/{repo}/manifests/{ref}", headers={"Accept": ", ".join(MANIFEST_TYPES)})
        if st != 200:
            return None
        return json.loads(body)

    def has_blob(self, repo: str, digest: str) -> bool:
        st, _, _ = self.call("HEAD", f"/v2/{repo}/blobs/{digest}")
        return st == 200

    def put_blob(self, repo: str, data: bytes) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if self.has_blob(repo, digest):
            return digest
        st, h, body = self.call("POST", f"/v2/{repo}/blobs/uploads/")
        if st != 202:
            raise SeedError(f"upload to {repo} refused: HTTP {st} {body[:200]!r}")
        loc = h.get("Location") or ""
        if not loc.startswith("http"):
            loc = self.base + loc
        sep = "&" if "?" in loc else "?"
        st, _, body = self.call("PUT", f"{loc}{sep}digest={urllib.parse.quote(digest)}", data=data,
                                headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(data))})
        if st != 201:
            raise SeedError(f"blob {digest} to {repo}: HTTP {st} {body[:200]!r}")
        return digest

    def put_blob_stream(self, repo: str, digest: str, size: int, stream) -> str:
        """Upload a blob of known digest and size from a file object, in one PUT, never whole in
        memory (a model layer is half a gigabyte). Nothing is sent when the blob is there."""
        if self.has_blob(repo, digest):
            return digest
        st, h, body = self.call("POST", f"/v2/{repo}/blobs/uploads/")
        if st != 202:
            raise SeedError(f"upload to {repo} refused: HTTP {st} {body[:200]!r}")
        loc = h.get("Location") or ""
        if not loc.startswith("http"):
            loc = self.base + loc
        sep = "&" if "?" in loc else "?"
        st, _, body = self.call("PUT", f"{loc}{sep}digest={urllib.parse.quote(digest)}", data=stream,
                                headers={"Content-Type": "application/octet-stream", "Content-Length": str(size)})
        if st != 201:
            raise SeedError(f"blob {digest} to {repo}: HTTP {st} {body[:200]!r}")
        return digest

    def put_manifest(self, repo: str, tag: str, body: bytes, media_type: str) -> str:
        st, h, out = self.call("PUT", f"/v2/{repo}/manifests/{tag}", data=body, headers={"Content-Type": media_type})
        if st != 201:
            raise SeedError(f"manifest {repo}:{tag}: HTTP {st} {out[:200]!r}")
        return h.get("Docker-Content-Digest") or ("sha256:" + hashlib.sha256(body).hexdigest())


# ------------------------------------------------------------------------------------------
# An upstream registry, read only (the pinned index of a one-platform image)


def _auth_params(header: str) -> dict:
    """The parameters of a 'Bearer realm="...",service="...",scope="..."' challenge."""
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return {}
    return {k.lower(): v for k, v in re.findall(r'([A-Za-z]+)="([^"]*)"', rest)}


class Upstream:
    """Reads manifests from an upstream registry, with the anonymous bearer token the registry's
    401 challenge asks for. opener(Request) is as in Http; tests pass their own."""

    def __init__(self, host: str, opener=None):
        self.host = host
        self.base = UPSTREAM_SERVER.get(host, f"https://{host}")
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=120))
        self.token: str | None = None
        self.requests = 0   # manifest requests made (each counts against an anonymous limit)

    def _get(self, url: str, headers: dict):
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            r = self.opener(req)
            return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read() if hasattr(e, "read") else b""

    def _token(self, challenge: str) -> str:
        p = _auth_params(challenge)
        if not p.get("realm"):
            raise SeedError(f"{self.host}: the registry asked for authentication it does not describe ({challenge!r})")
        q = {k: p[k] for k in ("service", "scope") if p.get(k)}
        url = p["realm"] + ("?" + urllib.parse.urlencode(q) if q else "")
        st, _, body = self._get(url, {"User-Agent": "sfab-seed/1"})
        if st != 200:
            raise SeedError(f"{self.host}: token request answered HTTP {st}")
        doc = json.loads(body or b"{}")
        tok = doc.get("token") or doc.get("access_token")
        if not tok:
            raise SeedError(f"{self.host}: the token answer holds no token")
        return tok

    def manifest(self, repo: str, ref: str) -> tuple[str, bytes]:
        """(media type, body) of one manifest, by tag or digest."""
        url = f"{self.base}/v2/{repo}/manifests/{ref}"
        headers = {"Accept": ", ".join(MANIFEST_TYPES), "User-Agent": "sfab-seed/1"}
        for attempt in (1, 2):
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self.requests += 1
            st, h, body = self._get(url, headers)
            if st == 401 and attempt == 1:
                self.token = self._token((h or {}).get("WWW-Authenticate") or "")
                continue
            if st != 200:
                raise SeedError(f"{self.host}/{repo}@{ref}: the registry answered HTTP {st}")
            mt = ((h or {}).get("Content-Type") or "").split(";")[0].strip()
            return mt or json.loads(body).get("mediaType", ""), body
        raise SeedError(f"{self.host}/{repo}@{ref}: refused after authenticating")


def platform_digest(index: dict, where: str) -> str:
    """The digest of the PLATFORM manifest an index lists: linux/amd64 with no variant, never an
    attestation (those list platform unknown/unknown)."""
    found = []
    for m in index.get("manifests") or []:
        pf = m.get("platform") or {}
        ann = m.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        if pf.get("os") == PLATFORM["os"] and pf.get("architecture") == PLATFORM["architecture"]:
            found.append((pf.get("variant") or "", m.get("digest")))
    plain = [d for v, d in found if not v]
    pick = plain or [d for _, d in found]
    if not pick or not pick[0] or not DIGEST_RE.match(str(pick[0])):
        raise SeedError(f"{where}: the pinned index lists no {PLATFORM_NAME} manifest")
    return str(pick[0])


def resolve_platform(im: Image, upstream: Upstream) -> str:
    """The digest of im's one platform manifest, read from the pinned index (checked by sha256).
    A pin that is already a single manifest is its own platform digest."""
    mt, body = upstream.manifest(im.repo, im.digest)
    have = "sha256:" + hashlib.sha256(body).hexdigest()
    if have != im.digest:
        raise SeedError(f"{im.source}: the registry served a manifest with sha256 {have}, not the pin")
    doc = json.loads(body)
    if (mt or doc.get("mediaType")) in INDEX_TYPES or "manifests" in doc:
        return platform_digest(doc, im.ref)
    return im.digest


# ------------------------------------------------------------------------------------------
# Charts


def chart_meta(tgz: bytes, chart: Chart) -> dict:
    """The OCI config helm writes: Chart.yaml's top-level scalar fields as JSON."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as t:
            member = next((m for m in t.getmembers() if m.name.count("/") == 1 and m.name.endswith("/Chart.yaml")), None)
            if member is None:
                raise SeedError(f"{chart.file} holds no <chart>/Chart.yaml")
            text = t.extractfile(member).read().decode("utf-8")
    except (tarfile.TarError, OSError) as e:
        raise SeedError(f"{chart.file}: not a chart archive ({e})") from None
    meta = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z]+):\s*(.*?)\s*$", line)
        if not m or m.group(1) not in CHART_FIELDS or not m.group(2) or m.group(2)[0] in "|>[{":
            continue
        v = m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        meta[m.group(1)] = v
    if meta.get("name") != chart.name or meta.get("version") != chart.version:
        raise SeedError(f"{chart.file}: Chart.yaml says {meta.get('name')} {meta.get('version')}, the pin {chart.name} {chart.version}")
    return meta


def chart_manifest(config: bytes, tgz: bytes, chart: Chart) -> bytes:
    """The OCI manifest of a helm chart, byte-stable (no creation time)."""
    doc = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": HELM_CONFIG, "digest": "sha256:" + hashlib.sha256(config).hexdigest(), "size": len(config)},
        "layers": [{"mediaType": HELM_LAYER, "digest": "sha256:" + hashlib.sha256(tgz).hexdigest(), "size": len(tgz)}],
        "annotations": {"org.opencontainers.image.title": chart.name, "org.opencontainers.image.version": chart.version},
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def index_url(index_text: str, chart: Chart, repo: str) -> str | None:
    """The chart's first URL in a Helm repository index.yaml, read without a YAML library.

    Under `entries:`, the chart's key holds a list of entries; an entry's own fields sit two
    columns right of its dash, so a dependency's version further in is never taken for the
    chart's. URLs may be relative to the repository."""
    lines = [ln for ln in index_text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]

    def ind(ln: str) -> int:
        return len(ln) - len(ln.lstrip(" "))

    i, n = 0, len(lines)
    while i < n and lines[i].rstrip() != "entries:":
        i += 1
    i += 1
    key_ind = None
    while i < n and ind(lines[i]) > 0:
        ln = lines[i]
        m = re.match(r"^\s*([^\s#'\"-][^:]*|'[^']*'|\"[^\"]*\"):\s*$", ln)
        if m and (key_ind is None or ind(ln) == key_ind):
            key_ind = ind(ln)
            name = m.group(1).strip().strip("\"'")
            i += 1
            block = []
            while i < n and ind(lines[i]) > 0 and not (ind(lines[i]) == key_ind and not lines[i].lstrip().startswith("- ")):
                block.append(lines[i])
                i += 1
            if name == chart.name:
                for e in _entries(block):
                    if e.get("version") == chart.version and e.get("urls"):
                        return urllib.parse.urljoin(repo + "/", e["urls"][0])
            continue
        i += 1
    return None


def _entries(block: list[str]) -> list[dict]:
    """The entries of one chart's list in index.yaml: version and urls of each."""
    out: list[dict] = []
    item_ind = None
    field_ind = None
    cur: dict | None = None
    in_urls = False
    for ln in block:
        k = len(ln) - len(ln.lstrip(" "))
        s = ln.strip()
        if s.startswith("- ") and (item_ind is None or k == item_ind):
            item_ind = k
            field_ind = k + 2
            cur = {}
            out.append(cur)
            s = s[2:]
            k = field_ind
            in_urls = False
        if cur is None:
            continue
        if in_urls and s.startswith("- ") and k >= field_ind:
            cur.setdefault("urls", []).append(s[2:].strip().strip("\"'"))
            continue
        if k != field_ind:
            continue
        m = re.match(r"^([A-Za-z]+):\s*(.*)$", s)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        in_urls = key == "urls" and not val
        if key == "version":
            cur["version"] = val.strip("\"'")
        elif key == "urls" and val.startswith("["):
            cur["urls"] = [u.strip().strip("\"'") for u in val.strip("[]").split(",") if u.strip()]
    return out


def fetch(url: str, opener=None) -> bytes:
    op = opener or (lambda req: urllib.request.urlopen(req, timeout=300))
    req = urllib.request.Request(url, headers={"User-Agent": "sfab-seed/1"})
    with op(req) as r:
        return r.read()


def chart_file(chart: Chart, vendor: Path, opener=None) -> bytes:
    """The chart's .tgz from <vendor>/charts/, downloaded once and checked against its sha256."""
    path = vendor / "charts" / chart.file
    if path.is_file():
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == chart.sha256:
            return data
        log(f"{path} does not match its sha256; downloading it again")
    tries = []
    if chart.url:
        tries.append(chart.url)
    if chart.repo:
        tries.append(f"{chart.repo}/{chart.file}")
    data = None
    for url in tries:
        try:
            data = fetch(url, opener)
            break
        except (urllib.error.URLError, OSError) as e:
            log(f"{url}: {e}")
    if data is None and chart.repo:
        idx = fetch(f"{chart.repo}/index.yaml", opener).decode("utf-8", "replace")
        url = index_url(idx, chart, chart.repo)
        if url is None:
            raise SeedError(f"{chart.repo}/index.yaml lists no {chart.name} {chart.version}")
        data = fetch(url, opener)
    if data is None:
        raise SeedError(f"could not download {chart.name} {chart.version}")
    have = hashlib.sha256(data).hexdigest()
    if have != chart.sha256:
        raise SeedError(f"{chart.file} has sha256 {have}, the pin says {chart.sha256}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return data


def push_chart(http: Http, chart: Chart, tgz: bytes) -> str:
    """Push one chart as an OCI artifact; nothing is written when it is already there."""
    layer = "sha256:" + chart.sha256
    have = http.manifest(chart.mirror_repo, chart.tag)
    if have and [x.get("digest") for x in have.get("layers") or []] == [layer]:
        return http.manifest_digest(chart.mirror_repo, chart.tag) or ""
    meta = chart_meta(tgz, chart)
    config = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    http.put_blob(chart.mirror_repo, config)
    http.put_blob(chart.mirror_repo, tgz)
    body = chart_manifest(config, tgz, chart)
    return http.put_manifest(chart.mirror_repo, chart.tag, body, OCI_MANIFEST)


# ------------------------------------------------------------------------------------------
# Images built here: a `docker save` archive pushed blob by blob


def saved_members(archive: Path) -> tuple[str, list[str]]:
    """(config member, [layer members]) of a `docker save` archive, from its manifest.json (the
    OCI layout Docker 25 and later writes keeps that file beside index.json)."""
    try:
        with tarfile.open(archive) as t:
            f = t.extractfile("manifest.json")
            man = json.load(f) if f else None
    except (tarfile.TarError, OSError, KeyError, ValueError) as e:
        raise SeedError(f"{archive}: not a docker save archive ({e})") from None
    if not isinstance(man, list) or len(man) != 1 or not man[0].get("Config"):
        raise SeedError(f"{archive}: manifest.json does not describe exactly one image")
    return str(man[0]["Config"]), [str(x) for x in man[0].get("Layers") or []]


def _member_digest(t: tarfile.TarFile, name: str) -> tuple[str, int]:
    f = t.extractfile(name)
    if f is None:
        raise SeedError(f"the archive has no file {name}")
    h, n = hashlib.sha256(), 0
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
        n += len(chunk)
    return "sha256:" + h.hexdigest(), n


def local_manifest(config_digest: str, config_size: int, layers: list) -> bytes:
    """The OCI manifest of an image built here: the saved config, then each saved layer as an
    uncompressed tar (its digest is the layer's diff id), byte-stable."""
    doc = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": config_size},
        "layers": [{"mediaType": OCI_LAYER_TAR, "digest": d, "size": n} for d, n in layers],
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def push_local(http: Http, im: Local, archive: Path) -> tuple[str, str]:
    """Push one saved image to <repo>:<tag>; (manifest digest, config digest). A blob the mirror
    already holds is not sent again."""
    cfg_name, layer_names = saved_members(archive)
    with tarfile.open(archive) as t:
        f = t.extractfile(cfg_name)
        if f is None:
            raise SeedError(f"{archive}: no config {cfg_name}")
        cfg = f.read()
        cfg_digest = http.put_blob(im.repo, cfg)
        layers = []
        for n in layer_names:
            d, size = _member_digest(t, n)
            http.put_blob_stream(im.repo, d, size, t.extractfile(n))
            layers.append((d, size))
    body = local_manifest(cfg_digest, len(cfg), layers)
    return http.put_manifest(im.repo, im.tag, body, OCI_MANIFEST), cfg_digest


def previous_local(record: dict | None) -> dict:
    """ref -> its SEED.json entry, for the images built here."""
    return {e["ref"]: e for e in (record or {}).get("local") or [] if e.get("ref")}


def seed_local(locals_, http: Http, inspect, save, record: dict | None = None) -> list:
    """Push every image built here. inspect(ref) gives the image's Docker id (SeedError when it
    is not built); save(Local) writes its archive and returns the path, which is removed after
    the push. An image whose id and served manifest match SEED.json is not saved again."""
    out = []
    before = previous_local(record)
    for im in locals_:
        iid = inspect(im.ref)
        have = http.manifest_digest(im.mirror_repo, im.tag)
        b = before.get(im.ref) or {}
        if have and b.get("image_id") == iid and b.get("served") == have:
            out.append((im, have, iid, b.get("config"), "present"))
            log(f"{im.mirror_path}: present ({have[:19]}, built image {iid[:19]})")
            continue
        log(f"{im.mirror_path}: pushing the built image {iid[:19]} from this host's Docker")
        path = save(im)
        try:
            served, cfg = push_local(http, im, Path(path))
        finally:
            Path(path).unlink(missing_ok=True)
        got = http.manifest_digest(im.mirror_repo, im.tag)
        if got != served:
            raise SeedError(f"{im.mirror_path}: the mirror answers {got}, the push wrote {served}")
        out.append((im, served, iid, cfg, "pushed"))
    return out


# ------------------------------------------------------------------------------------------
# docker and skopeo


def docker(args: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(["docker", *args], capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise SeedError(f"docker {' '.join(args[:3])} ...: exit {r.returncode}: {(r.stderr or '').strip()[-400:]}")
    return r


def skopeo_args(skopeo_image: str, im: Image, dest: str, name: str, source_digest: str | None = None) -> list[str]:
    """docker run arguments for one copy: digests kept, plain HTTP to the mirror. Every platform
    of the pinned index, or (source_digest given) that one manifest only."""
    args = ["run", "--rm", "--name", name, "--network", "host", skopeo_image, "copy"]
    if source_digest is None:
        args.append("--all")
    args += ["--preserve-digests", "--retry-times", "3", "--dest-tls-verify=false",
             f"docker://{im.host}/{im.repo}@{source_digest or im.digest}", f"docker://{dest}/{im.mirror_path}"]
    return args


def registry_args(name: str, image: str, data: Path, port: int) -> list[str]:
    """docker run arguments for the seeding registry: host network, loopback only, data read-write."""
    return ["run", "-d", "--name", name, "--network", "host", "--no-healthcheck",
            "-e", f"REGISTRY_HTTP_ADDR=127.0.0.1:{port}",
            "-v", f"{data}:/var/lib/registry", image, "/etc/sfab/registry-seed.yml"]


@dataclass
class Result:
    images: list = field(default_factory=list)   # (Image, served digest, action)
    charts: list = field(default_factory=list)   # (Chart, manifest digest, action)
    local: list = field(default_factory=list)    # (Local, served digest, image id, config digest, action)


def previous_served(record: dict | None) -> dict:
    """ref -> (pinned digest, served digest) from an earlier SEED.json."""
    out = {}
    for e in (record or {}).get("images") or []:
        if e.get("ref") and e.get("digest"):
            out[e["ref"]] = (e["digest"], e.get("served") or e["digest"])
    return out


def seed(images, charts, http: Http, copy, vendor: Path, opener=None, upstream=None, record: dict | None = None) -> Result:
    """Copy every image and push every chart into the registry behind http. copy(Image, digest)
    makes one copy (digest None: every platform of the pin); upstream(host) gives the Upstream
    a one-platform image's index is read from. record is the data directory's SEED.json, if any:
    a one-platform image it lists, and that the mirror still serves, is not read again. Every
    result is read back from the registry."""
    res = Result()
    before = previous_served(record)
    ups: dict = {}

    def up(host: str) -> Upstream:
        if host not in ups:
            ups[host] = upstream(host) if upstream else Upstream(host, opener)
        return ups[host]

    for im in images:
        have = http.manifest_digest(im.mirror_repo, im.tag)
        want = im.digest
        if im.platform:
            pinned, served = before.get(im.ref, (None, None))
            if pinned == im.digest and served and have == served:
                res.images.append((im, have, "present"))
                log(f"{im.mirror_path}: present ({im.platform} {served[:19]} of {im.digest[:19]})")
                continue
            want = resolve_platform(im, up(im.host))
        if have == want:
            res.images.append((im, have, "present"))
            log(f"{im.mirror_path}: present ({want[:19]})")
            continue
        if have:
            log(f"{im.mirror_path}: holds {have}, the pin is {want}; copying the pin")
        log(f"{im.mirror_path}: copying {im.host}/{im.repo}@{want}" + (f" ({im.platform} of {im.digest})" if im.platform else ""))
        copy(im, want if im.platform else None)
        got = http.manifest_digest(im.mirror_repo, im.tag)
        if got != want:
            raise SeedError(f"{im.mirror_path}: the mirror answers {got}, the pin is {want}")
        res.images.append((im, got, "copied"))
    for c in charts:
        tgz = chart_file(c, vendor, opener)
        before_c = http.manifest(c.mirror_repo, c.tag)
        digest = push_chart(http, c, tgz)
        layers = [x.get("digest") for x in (http.manifest(c.mirror_repo, c.tag) or {}).get("layers") or []]
        if layers != ["sha256:" + c.sha256]:
            raise SeedError(f"{c.mirror_path}: the mirror holds layers {layers}, the pin is sha256:{c.sha256}")
        action = "present" if before_c and [x.get("digest") for x in before_c.get("layers") or []] == layers else "pushed"
        res.charts.append((c, digest, action))
        log(f"{c.mirror_path}: {action}")
    return res


def seed_record(res: Result, versions_sha: str) -> str:
    doc = {
        "schema": SCHEMA,
        "versions_sha256": versions_sha,
        "upstreams": upstreams([im for im, _, _ in res.images]),
        "images": [{"id": im.id, "ref": im.ref, "digest": im.digest, "mirror": im.mirror_path,
                    "platform": im.platform or "all", "served": served} for im, served, _ in res.images],
        "charts": [{"id": c.id, "name": c.name, "version": c.version, "sha256": c.sha256, "mirror": c.mirror_path,
                    "manifest": d} for c, d, _ in res.charts],
    }
    if res.local:
        doc["local"] = [{"id": im.id, "ref": im.ref, "mirror": im.mirror_path, "image_id": iid, "config": cfg,
                         "served": served} for im, served, iid, cfg, _ in res.local]
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


# ------------------------------------------------------------------------------------------
# Offline check of a data directory (the registry's filesystem layout)


def _store(data: Path) -> Path:
    return data / "docker" / "registry" / "v2"


def stored_tag(data: Path, repo: str, tag: str) -> str | None:
    link = _store(data) / "repositories" / repo / "_manifests" / "tags" / tag / "current" / "link"
    try:
        return link.read_text().strip()
    except OSError:
        return None


def stored_blob(data: Path, digest: str) -> bytes | None:
    algo, _, hexd = digest.partition(":")
    p = _store(data) / "blobs" / algo / hexd[:2] / hexd / "data"
    try:
        return p.read_bytes()
    except OSError:
        return None


def has_blob_file(data: Path, digest: str) -> bool:
    """Whether the data directory holds a blob, without reading it (a model layer is large)."""
    algo, _, hexd = str(digest).partition(":")
    return bool(hexd) and (_store(data) / "blobs" / algo / hexd[:2] / hexd / "data").is_file()


def read_record(data: Path) -> dict | None:
    """The data directory's SEED.json, or None when there is none (or it does not parse)."""
    try:
        return json.loads((Path(data) / SEED_FILE).read_text())
    except (OSError, ValueError):
        return None


def check_data(data: Path, images, charts, record: dict | None = None, local=()) -> list[str]:
    """Problems with data: every pinned tag must point at the pinned digest (a one-platform image:
    at the platform digest SEED.json records for that pin), the manifest blob must be there, and
    for a chart the pinned .tgz must be its one layer. An image built here must be in SEED.json,
    its tag on the manifest recorded there, with every blob that manifest names."""
    problems = []
    rec = record if record is not None else read_record(data)
    served = previous_served(rec)
    built = previous_local(rec)
    for im in local:
        e = built.get(im.ref)
        if not e or not e.get("served"):
            problems.append(f"{im.mirror_path}: SEED.json records no push of the built image; build it, then run make -C images registry-seed")
            continue
        got = stored_tag(data, im.mirror_repo, im.tag)
        blob = stored_blob(data, got) if got else None
        if got != e["served"]:
            problems.append(f"{im.mirror_path}: {'missing' if got is None else 'holds ' + got}, SEED.json records {e['served']}")
        elif blob is None:
            problems.append(f"{im.mirror_path}: manifest blob {got} missing")
        else:
            doc = json.loads(blob)
            for d in [doc.get("config", {}).get("digest")] + [x.get("digest") for x in doc.get("layers") or []]:
                if not d or not has_blob_file(data, d):
                    problems.append(f"{im.mirror_path}: blob {d} missing")
                    break
    for im in images:
        want = im.digest
        if im.platform:
            pinned, s = served.get(im.ref, (None, None))
            if pinned != im.digest:
                problems.append(f"{im.mirror_path}: SEED.json records no {im.platform} copy of {im.digest}; run make -C images registry-seed")
                continue
            want = s
        got = stored_tag(data, im.mirror_repo, im.tag)
        if got != want:
            problems.append(f"{im.mirror_path}: {'missing' if got is None else 'holds ' + got}, the pin is {want}")
        elif stored_blob(data, got) is None:
            problems.append(f"{im.mirror_path}: manifest blob {got} missing")
    for c in charts:
        got = stored_tag(data, c.mirror_repo, c.tag)
        blob = stored_blob(data, got) if got else None
        if blob is None:
            problems.append(f"{c.mirror_path}: missing")
            continue
        layers = [x.get("digest") for x in json.loads(blob).get("layers") or []]
        if layers != ["sha256:" + c.sha256]:
            problems.append(f"{c.mirror_path}: layers {layers}, the pin is sha256:{c.sha256}")
        elif stored_blob(data, layers[0]) is None:
            problems.append(f"{c.mirror_path}: chart blob missing")
    return problems


# ------------------------------------------------------------------------------------------
# The data directory and its link into the checkout


def link_data(data: Path, link: Path | None) -> None:
    """Make link (images/registry/data, which the topology binds) point at data when they differ."""
    if link is None:
        return
    data = data.resolve()
    if link.is_symlink():
        if link.resolve() == data:
            return
        link.unlink()
    elif link.exists():
        if link.resolve() == data:
            return
        if link.is_dir() and not any(link.iterdir()):
            link.rmdir()
        else:
            raise SeedError(f"{link} is a directory with data in it; move it to {data} or seed without SFAB_IMAGE_STORE")
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(data)
    log(f"{link} -> {data}")


def wait_ready(http: Http, seconds: int = 60) -> None:
    for _ in range(seconds * 2):
        if http.ping():
            return
        time.sleep(0.5)
    raise SeedError(f"the seeding registry did not answer at {http.base}/v2/ within {seconds}s")


def docker_image_id(ref: str) -> str:
    r = docker(["image", "inspect", "--format", "{{.Id}}", ref], check=False)
    iid = (r.stdout or "").strip()
    if r.returncode != 0 or not DIGEST_RE.match(iid):
        raise SeedError(f"{ref} is not in this host's Docker: build it first (make -C images all)")
    return iid


def run(args, images, charts, versions_sha: str, local=()) -> int:
    data = Path(args.data).resolve()
    data.mkdir(parents=True, exist_ok=True)
    http = Http(f"http://127.0.0.1:{args.port}")
    if http.ping():
        raise SeedError(f"something already answers on 127.0.0.1:{args.port}; pick another SEED_PORT")
    copier = f"{args.name}-copy"
    for leftover in (args.name, copier):
        if docker(["container", "inspect", leftover], check=False).returncode == 0:
            log(f"removing the leftover seeding container {leftover}")
            docker(["rm", "-f", leftover])
    record = read_record(data)
    docker(registry_args(args.name, args.image, data, args.port))
    try:
        wait_ready(http)
        dest = f"127.0.0.1:{args.port}"

        def copy(im: Image, digest: str | None) -> None:
            r = docker(skopeo_args(args.skopeo, im, dest, copier, digest), check=False, capture=False)
            if r.returncode != 0:
                raise SeedError(f"skopeo could not copy {im.host}/{im.repo}@{digest or im.digest} (exit {r.returncode})")

        res = seed(images, charts, http, copy, Path(args.vendor), record=record)
        work = Path(getattr(args, "work", None) or Path(args.vendor) / "tmp")

        def save(im: Local) -> Path:
            work.mkdir(parents=True, exist_ok=True)
            out = work / (im.mirror_path.replace("/", "_").replace(":", "_") + ".tar")
            docker(["save", "-o", str(out), im.ref])
            return out

        res.local = seed_local(local, http, docker_image_id, save, record=record)
    finally:
        docker(["rm", "-f", args.name], check=False)
    tmp = data / (SEED_FILE + ".part")
    tmp.write_text(seed_record(res, versions_sha))
    os.replace(tmp, data / SEED_FILE)
    link_data(data, Path(args.link) if args.link else None)
    n_new = sum(1 for x in res.images if x[2] == "copied")
    c_new = sum(1 for x in res.charts if x[2] == "pushed")
    l_new = sum(1 for x in res.local if x[4] == "pushed")
    log(f"{len(res.images)} images ({n_new} copied), {len(res.charts)} charts ({c_new} pushed), "
        f"{len(res.local)} built here ({l_new} pushed); upstreams {' '.join(upstreams(images))}; data {data}")
    return 0


# ------------------------------------------------------------------------------------------


def load_tree(path: str | None) -> tuple[dict, str]:
    p = Path(path) if path else pins.VERSIONS
    return pins.load(p), hashlib.sha256(p.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="seed.py", description=__doc__.strip().splitlines()[0])
    ap.add_argument("--versions", help="versions.yaml (default spec/versions.yaml)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", help="print every image and chart to seed")
    rp = sub.add_parser("run", help="copy every pin into the data directory")
    rp.add_argument("--data", required=True)
    rp.add_argument("--image", required=True, help="the registry image (sfab/registry:2)")
    rp.add_argument("--skopeo", required=True, help="the pinned skopeo image")
    rp.add_argument("--name", default="sfab-registry-seed")
    rp.add_argument("--port", type=int, default=5099)
    rp.add_argument("--vendor", default=str(ROOT / "vendor"))
    rp.add_argument("--link", help="a path to point at --data (images/registry/data)")
    rp.add_argument("--work", help="where docker save writes an image built here (default <vendor>/tmp)")
    cp = sub.add_parser("check", help="verify a data directory holds every pin (offline)")
    cp.add_argument("--data", required=True)
    hp = sub.add_parser("hosts-toml", help="print the containerd hosts.toml for one upstream")
    hp.add_argument("--mirror", required=True, help="address:port of the lab's registry")
    hp.add_argument("--scheme", default="http")
    hp.add_argument("upstream", nargs="?", help="the upstream host (none with --local)")
    hp.add_argument("--local", action="store_true", help="the file for the images built here, served by the mirror itself")
    hp.add_argument("--ca", default=None, help="the CA file a node verifies an HTTPS mirror against (the lab root)")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "hosts-toml":
            if a.local == bool(a.upstream):
                raise SeedError("hosts-toml takes an upstream host, or --local")
            sys.stdout.write(hosts_toml_local(a.mirror, a.scheme, a.ca) if a.local else hosts_toml(a.upstream, a.mirror, a.scheme, a.ca))
            return 0
        tree, vsha = load_tree(a.versions)
        images, charts = collect(tree)
        local = collect_local(tree)
        if a.cmd == "plan":
            for im in images:
                only = f", {im.platform} only" if im.platform else ""
                print(f"image  {im.mirror_path:<72} {im.digest}  ({im.id}{only})")
            for c in charts:
                print(f"chart  {c.mirror_path:<72} sha256:{c.sha256}  ({c.id})")
            for im in local:
                print(f"local  {im.mirror_path:<72} {'built here':<71}  ({im.id}, from this host's Docker)")
            print(f"{len(images)} images from {' '.join(upstreams(images)) or 'no registry'}, {len(charts)} charts, "
                  f"{len(local)} images built here")
            return 0
        if a.cmd == "check":
            data = Path(a.data)
            problems = check_data(data, images, charts, local=local)
            for p in problems:
                print(f"FAIL  {p}")
            n = len(images) + len(charts) + len(local)
            print(f"{n - len(problems)} of {n} pins in {data}")
            return 1 if problems else 0
        if not shutil.which("docker"):
            raise SeedError("docker is not on PATH")
        return run(a, images, charts, vsha, local=local)
    except (SeedError, pins.PinError, OSError, ValueError) as e:
        print(f"seed.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
