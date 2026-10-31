"""Storage: bootstrap/<node>/setup.json for TrueNAS, and the democratic-csi values in
bootstrap/k8s/60-democratic-csi-<class>.yaml (FRAMEWORK.md sections 2.2 and 3.4).

setup.json is what common/storage/truenas-setup.py does to the TrueNAS system, through its
middleware API, once the image's launcher has finished its own first boot (the launcher sets the
administrator's password, enables SSH, caps the ZFS ARC and builds the pool). In order:

  network   the management return route first: the setup session reaches the system on its
            containerlab management address through the vrnetlab VM's user-mode NIC, which keeps
            the client's own address, so replies to the management network must keep a way back
            through that NIC when the default route moves to the firewall. Then the data bond
            (four members, LACP fast, layer3+4, MTU 9000, the data address), the storage
            management NIC, and the user-mode NIC made static with no gateway, committed with
            rollback armed and a check-in. Then the default gateway (the firewall's storage
            management unit), DNS and NTP (the bastion).
  services  the datasets democratic-csi works under, NFS bound to the data address, and an
            NVMe-oF TCP port on the data address.
  users     the CSI user, an administrator of its own, so the driver's API sessions never count
            against the administrator's.
  csi       one Kubernetes Secret per class holding the driver's configuration with the password,
            applied from the bastion. The values files below name those Secrets.

Bond members are listed by container port. TrueNAS's NIC MACs are the launcher's copies of the
container ports' MACs, which containerlab draws at each deploy, so the setup maps each member by
reading the container port's MAC at run time.

Credentials. containerlab's generic_vm kind gives the launcher --username and --password built
from the node's USERNAME and PASSWORD env, which the topology fills from state/secrets.env, and
the launcher sets truenas_admin's password to its --password at first boot (it creates a second
administrator only for a username other than truenas_admin and root). So the generated password is the
one TrueNAS holds; setup.json names where the setup reads it, never the value.

The CSI driver calls TrueNAS's API on its management address (csi.api: mgmt), over HTTPS, through
the firewall's csi-to-storage-api rule: storage data sits on its own Layer 2 VLAN with no gateway,
which no node's API traffic uses, so the reply leaves by the management bond the request came in
on. The web interface and API are bound to the management address and to the user-mode NIC the
harness reaches the system through (the ui step), never to the data address. The NVMe/TCP class is the cluster's default, a lab
choice: the driver's README marks every one of its freenas-api drivers experimental. NFS serves
ReadWriteMany.

The driver image is the project's `next` line, pinned by digest in spec/versions.yaml: it adds a
websocket client for TrueNAS's JSON-RPC API, which the last tagged release (v1.9.5) does not
have. The driver configuration follows the driver's own freenas-api examples.

Nothing here is a secret. The setup reads the TrueNAS password at run time from what the
launcher was given, and writes the CSI Secrets straight into the cluster.
"""

from __future__ import annotations

import json
import re

from .. import addr
from ..model import Model, Storage
from . import RenderError

SCHEMA = 1

# The TrueNAS middleware API: JSON-RPC 2.0 over a websocket, on the port the launcher forwards.
API_PORT = 80
# The CSI driver's API calls: HTTPS on the management address (TrueNAS's own certificate).
CSI_API_PORT = 443
API_PATH = "/api/current"
# The administrator the image's launcher always has; its password is the launcher's --password.
ADMIN_USER = "truenas_admin"
# The IANA port for NVMe over TCP.
NVME_TCP_PORT = 4420
# The vrnetlab VM's user-mode NIC: QEMU's user network gives the guest .15 and its gateway .2.
QEMU_USER_GW_HOST = 2
QEMU_USER_GUEST_HOST = 15
# interface.commit: rollback armed, the check-in window and the call's own timeout. Re-addressing
# the user-mode NIC, which carries the setup session, can stall the call for about two minutes.
COMMIT = {"rollback": True, "checkin_timeout_s": 600, "call_timeout_s": 420}

# democratic-csi, per class: the driver, the service it needs on TrueNAS, and the StorageClass.
CSI_NAMESPACE = "democratic-csi"
CSI_CLASSES = {
    "nvmeof": {"driver": "freenas-api-nvmeof", "service": "nvmet", "fs_type": "ext4"},
    "nfs": {"driver": "freenas-api-nfs", "service": "nfs", "fs_type": "nfs"},
}
# The key the driver reads its configuration from, inside the config Secret.
CSI_CONFIG_KEY = "driver-config-file.yaml"
# Fields of the driver configuration only the setup knows: the password, and the id TrueNAS gave
# the NVMe-oF port when it was created.
CSI_RUNTIME_FIELDS = ("httpConnection.password", "nvmeof.ports")
# The values file of each class, under bootstrap/k8s/ (render/k8s.py writes every other file there).
VALUES_FILE = "60-democratic-csi-{cls}.yaml"
# Image keys in versions.yaml kubernetes.democratic_csi.images, and where each goes in the values.
# The node's cleanup sidecar runs the driver image: it needs only /bin/sh, sleep and rm, which the
# driver's Debian base has, and the node holds that image already. The chart's own default
# (busybox, pinned as cleanup with used: false) would be the one image the stack pulls from Docker
# Hub, which the registry seed copies for one platform only, so a pull by its index digest fails.
CSI_IMAGES = (
    ("driver", ("controller", "driver")),
    ("driver", ("node", "driver")),
    ("provisioner", ("controller", "externalProvisioner")),
    ("attacher", ("controller", "externalAttacher")),
    ("resizer", ("controller", "externalResizer")),
    ("node_driver_registrar", ("node", "driverRegistrar")),
    ("driver", ("node", "cleanup")),
    ("csi_proxy", ("csiProxy",)),
)


# --------------------------------------------------------------------------------------------
# helpers


def _json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def truenas_nodes(model: Model) -> list:
    return [s for s in model.storage.values() if s.product == "truenas"]


def _settings(s: Storage) -> dict:
    return dict(s.settings or {})


def _pool(s: Storage) -> str:
    pool = _settings(s).get("pool")
    if not pool:
        raise RenderError(f"{s.name}: storage.pool is not set")
    return pool


def datasets(s: Storage) -> list:
    """Every dataset the setup makes, parents first, in spec order: tank/k8s, tank/k8s/nvmeof ..."""
    pool = _pool(s)
    out: list = []
    for d in _settings(s).get("datasets") or []:
        parts = str(d).strip("/").split("/")
        for i in range(1, len(parts) + 1):
            full = "/".join([pool] + parts[:i])
            if full not in out:
                out.append(full)
    return out


def csi_settings(s: Storage) -> dict | None:
    return _settings(s).get("csi")


def csi_classes(s: Storage) -> list:
    csi = csi_settings(s) or {}
    classes = list(csi.get("classes") or [])
    for c in classes:
        if c not in CSI_CLASSES:
            raise RenderError(f"{s.name}: csi class {c!r} is not one of {', '.join(CSI_CLASSES)}")
    default = csi.get("default_class")
    if classes and default not in classes:
        raise RenderError(f"{s.name}: csi.default_class {default!r} is not one of the classes {classes}")
    return classes


def storage_class(cls: str) -> str:
    return f"truenas-{cls}"


def release(cls: str) -> str:
    return f"truenas-{cls}"


def config_secret(cls: str) -> str:
    return f"truenas-{cls}-driver-config"


def csi_api_address(s: Storage) -> str:
    """The address the CSI driver calls: the data address (csi.api: data) or the management one."""
    api = (csi_settings(s) or {}).get("api", "data")
    if api == "data":
        cidr = s.data.address if s.data else None
    elif api == "mgmt":
        cidr = s.mgmt_if.address if s.mgmt_if else None
    else:
        raise RenderError(f"{s.name}: csi.api {api!r} must be data or mgmt")
    if not cidr:
        raise RenderError(f"{s.name}: csi.api is {api}, but the node has no {api} address")
    return str(addr.ip(cidr))


def _data_ip(s: Storage) -> str | None:
    return str(addr.ip(s.data.address)) if s.data else None


def _qemu_user(model: Model) -> dict:
    slirp = (model.common.get("switch") or {}).get("slirp") or "10.0.0.0/24"
    return {"prefix": slirp, "gateway": addr.host(slirp, QEMU_USER_GW_HOST),
            "address": addr.host_cidr(slirp, QEMU_USER_GUEST_HOST)}


def _route(r, qemu: dict) -> dict:
    d = {"dest": r.dest, "first": bool(r.first), "id": r.id}
    if r.via == "qemu-user":
        d.update({"via": "qemu-user", "gateway": qemu["gateway"],
                  "description": "management network via the VM's user-mode NIC"})
    elif r.via:
        d.update({"via": r.via, "gateway": r.via, "description": f"{r.dest} via {r.via}"})
    else:
        raise RenderError(f"route {r.dest} has no next hop")
    return d


def _bastion(model: Model) -> str | None:
    for n in model.nodes.values():
        if n.kind == "bastion":
            return n.name
    return None


def _csi_enabled(model: Model) -> bool:
    return bool(model.features.get("k8s")) and bool(model.features.get("storage_setup")) and model.k8s is not None


# --------------------------------------------------------------------------------------------
# democratic-csi driver configuration (without the runtime fields)


def driver_config(model: Model, s: Storage, cls: str) -> dict:
    """The driver's configuration for one class, as the config Secret will hold it, minus the
    password and the NVMe-oF port ids (CSI_RUNTIME_FIELDS), which truenas-setup.py fills in."""
    csi = csi_settings(s) or {}
    pool = _pool(s)
    ds = datasets(s)
    parent = f"{pool}/k8s/{cls}"
    snaps = f"{pool}/k8s/{cls}-snaps"
    if parent not in ds:
        raise RenderError(f"{s.name}: csi class {cls} needs the dataset k8s/{cls}")
    host = csi_api_address(s)
    data_ip = str(addr.ip(s.data.address))
    zfs: dict = {"datasetParentName": parent}
    if snaps in ds:
        zfs["detachedSnapshotsDatasetParentName"] = snaps
    cfg: dict = {
        "driver": CSI_CLASSES[cls]["driver"],
        "instance_id": f"{model.org.short}-{s.name}-{cls}",
        "httpConnection": {"protocol": "https" if host != _data_ip(s) else "http", "host": host,
                           "port": CSI_API_PORT if host != _data_ip(s) else API_PORT,
                           "username": csi.get("user") or "democratic-csi", "allowInsecure": True},
        "zfs": zfs,
    }
    if cls == "nvmeof":
        zfs.update({"zvolCompression": None, "zvolDedup": None, "zvolEnableReservation": False,
                    "zvolBlocksize": "16K"})
        cfg["nvmeof"] = {"transports": [f"tcp://{data_ip}:{NVME_TCP_PORT}"],
                         "namePrefix": "csi-", "nameSuffix": f"-{model.org.short}",
                         "subsystemTemplate": {}, "namespaceTemplate": {}}
        # crc16 keeps the volume ids, and so the NVMe subsystem names, short.
        cfg["_private"] = {"csi": {"volume": {"idHash": {"strategy": "crc16"}}}}
    elif cls == "nfs":
        zfs.update({"datasetEnableQuotas": True, "datasetEnableReservation": False,
                    "datasetPermissionsMode": "0777", "datasetPermissionsUser": 0,
                    "datasetPermissionsGroup": 0})
        cfg["nfs"] = {"shareHost": data_ip, "shareAlldirs": False, "shareAllowedHosts": [],
                      "shareAllowedNetworks": [addr.prefix_of(s.data.address)],
                      "shareMaprootUser": "root", "shareMaprootGroup": "root",
                      "shareMapallUser": "", "shareMapallGroup": ""}
    return cfg


# --------------------------------------------------------------------------------------------
# setup.json


def truenas_setup(model: Model, s: Storage, ctx) -> str:
    st = _settings(s)
    if not s.data or not s.mgmt_if:
        raise RenderError(f"{s.name}: TrueNAS needs a data bond and a management interface")
    if not s.gateway:
        raise RenderError(f"{s.name}: no default gateway (storage.gateway)")
    qemu = _qemu_user(model)
    routes = sorted((_route(r, qemu) for r in s.routes), key=lambda d: (not d["first"],))
    data_ip = str(addr.ip(s.data.address))
    lacp = s.data.lacp or {}

    def peer(eth):
        n = s.nic(eth)
        return str(n.peer) if n is not None and n.peer is not None else None

    members = [{"eth": e, "match": "mac", "peer": peer(e)} for e in s.data.nics]
    mgmt_eth = s.mgmt_if.nics[0]
    mlacp = s.mgmt_if.lacp or {}
    if len(s.mgmt_if.nics) > 1:
        # the management bond: one leg on each switch of the pair
        mgmt = {"name": "bond1", "members": [{"eth": e, "match": "mac", "peer": peer(e)} for e in s.mgmt_if.nics],
                "protocol": "LACP", "lacpdu_rate": str(mlacp.get("rate", "fast")).upper(),
                "xmit_hash_policy": str(mlacp.get("hash", "layer3+4")).upper(), "mtu": s.mgmt_if.mtu or 1500,
                "address": s.mgmt_if.address, "vlan": s.mgmt_if.vlan}
    else:
        mgmt = {"eth": mgmt_eth, "match": "mac", "peer": peer(mgmt_eth), "address": s.mgmt_if.address,
                "vlan": s.mgmt_if.vlan, "mtu": s.mgmt_if.mtu}
    services: dict = {}
    for svc in st.get("services") or []:
        if svc == "nfs":
            services["nfs"] = {"bindip": [data_ip], "protocols": ["NFSV3", "NFSV4"]}
        elif svc == "nvmet":
            services["nvmet"] = {"ports": [{"traddr": data_ip, "trsvcid": NVME_TCP_PORT, "trtype": "TCP"}]}
        else:
            raise RenderError(f"{s.name}: service {svc!r} is not one the setup knows (nfs, nvmet)")

    doc: dict = {
        "about": (f"{model.lab} {s.name}: rendered from {ctx.profile_file(model)}; edit the spec and run make render. "
                  "common/storage/truenas-setup.py applies it through the TrueNAS API, in the order of steps."),
        "schema": SCHEMA,
        "lab": model.lab,
        "node": s.name,
        "container": s.container,
        "product": s.product,
        "decision": s.decision,
        "hostname": s.name,
        "domain": model.org.names,
        "steps": ["wait", "network", "services", "users", "csi", "ui"],
        # where the web interface and API answer: the management address, and the user-mode NIC the
        # harness's setup session arrives on (a lab harness path, never a design network)
        "ui": {"addresses": [str(addr.ip(s.mgmt_if.address)), str(addr.ip(qemu["address"]))]},
        "api": {"host": s.mgmt, "port": API_PORT, "path": API_PATH, "user": ADMIN_USER,
                "password_from": "the launcher's --password, read from the container"},
        "pool": _pool(s),
        "network": {
            "qemu_user": qemu,
            "routes": routes,
            "bond": {"name": "bond0", "members": members, "protocol": "LACP",
                     "lacpdu_rate": str(lacp.get("rate", "fast")).upper(),
                     "xmit_hash_policy": str(lacp.get("hash", "layer3+4")).upper(),
                     "mtu": s.data.mtu or 9000, "address": s.data.address, "vlan": s.data.vlan},
            "mgmt": mgmt,
            "gateway": s.gateway,
            "nameservers": list(s.dns),
            "ntp": list(s.ntp),
            "commit": dict(COMMIT),
        },
        "datasets": datasets(s),
        "services": services,
    }
    if st.get("arc_max_mb") is not None:
        doc["arc_max_mb"] = st["arc_max_mb"]
    csi = csi_settings(s)
    if csi:
        classes = csi_classes(s)
        for c in classes:
            if CSI_CLASSES[c]["service"] not in services:
                raise RenderError(f"{s.name}: csi class {c} needs the {CSI_CLASSES[c]['service']} service")
        user = csi.get("user") or "democratic-csi"
        block: dict = {
            "api": csi.get("api", "data"),
            "api_address": csi_api_address(s),
            "default_class": csi.get("default_class"),
            "users": [{"username": user, "full_name": "Kubernetes CSI driver", "administrator": True,
                       "password_from": "the administrator's password"}],
            "classes": [{"name": c, "storage_class": storage_class(c), "release": release(c),
                         "config_secret": config_secret(c), "config_key": CSI_CONFIG_KEY,
                         "driver_config": driver_config(model, s, c)} for c in classes],
            "runtime_fields": list(CSI_RUNTIME_FIELDS),
        }
        if _csi_enabled(model) and model.k8s is not None and model.k8s.init:
            # the harness's kubectl: common/bin/sfab-kubectl with the lab's render directory (relative to
            # the repository root), kubectl with the admin kubeconfig on the init node over SSH
            from .k8s import SFAB_KUBECTL, _render_dir  # noqa: PLC0415

            block["kubernetes"] = {"namespace": CSI_NAMESPACE, "kubectl": [SFAB_KUBECTL, _render_dir(model, ctx)],
                                   "secret_labels": {model.k8s.labels["decision"]: s.decision} if s.decision else {}}
        doc["csi"] = block
    return _json(doc)


# --------------------------------------------------------------------------------------------
# democratic-csi values (helm), one release per class


def _pins(model: Model) -> dict:
    k8s = (model.meta.versions or {}).get("kubernetes") or {}
    pins = k8s.get("democratic_csi") or {}
    chart = pins.get("chart") or {}
    imgs = pins.get("images") or {}
    missing = [k for k in ("name", "repo", "version") if not chart.get(k)]
    missing += [f"images.{key}" for key, _ in CSI_IMAGES if not (imgs.get(key) or {}).get("digest")]
    if missing:
        raise RenderError("spec/versions.yaml kubernetes.democratic_csi is missing " + ", ".join(sorted(set(missing))))
    return pins


def _image(pin: dict) -> dict:
    """{registry, tag} the chart's way: registry is the repository, tag is '<tag>@<digest>'."""
    ref = pin["ref"]
    repo, sep, tag = ref.rpartition(":")
    if not sep or "/" in tag:
        raise RenderError(f"image {ref!r} must be <repository>:<tag>")
    return {"registry": repo, "tag": f"{tag}@{pin['digest']}"}


def csi_releases(model: Model) -> list:
    """The democratic-csi Helm releases of this lab, one per class, for render/k8s.py and the
    finish stage: release, namespace, chart, repo, version, sha256 and values (the file name
    under bootstrap/k8s/). They install after truenas-setup.py, which writes their config Secrets."""
    if not _csi_enabled(model):
        return []
    nodes = [s for s in truenas_nodes(model) if csi_settings(s)]
    if not nodes:
        return []
    chart = _pins(model)["chart"]
    return [{"release": release(c), "namespace": CSI_NAMESPACE, "chart": chart["name"], "repo": chart["repo"],
             "version": str(chart["version"]), "sha256": chart.get("sha256"), "values": VALUES_FILE.format(cls=c),
             "storage_class": storage_class(c), "config_secret": config_secret(c),
             "default": c == (csi_settings(nodes[0]) or {}).get("default_class")}
            for c in csi_classes(nodes[0])]


def values(model: Model, s: Storage, cls: str) -> dict:
    pins = _pins(model)
    imgs = pins["images"]
    csi = csi_settings(s) or {}
    default = cls == csi.get("default_class")
    sc: dict = {"name": storage_class(cls), "defaultClass": default, "reclaimPolicy": "Delete",
                "volumeBindingMode": "Immediate", "allowVolumeExpansion": True,
                "parameters": {"fsType": CSI_CLASSES[cls]["fs_type"], "detachedVolumesFromSnapshots": "false"},
                "mountOptions": []}
    if s.decision and model.k8s is not None:
        sc["labels"] = {model.k8s.labels["decision"]: s.decision}
    v: dict = {
        "csiDriver": {"name": f"org.democratic-csi.{cls}"},
        "storageClasses": [sc],
        "volumeSnapshotClasses": [],
        "controller": {"externalSnapshotter": {"enabled": False}},
        "node": {"hostPID": True, "tolerations": [{"operator": "Exists"}]},
        "csiProxy": {},
        "driver": {"existingConfigSecret": config_secret(cls), "config": {"driver": CSI_CLASSES[cls]["driver"]}},
    }
    for key, path in CSI_IMAGES:
        d = v
        for p in path:
            d = d.setdefault(p, {})
        d["image"] = _image(imgs[key])
    return v


# A small YAML writer for the values files: mappings keep the order given, strings are quoted
# whenever a plain scalar could be read as something else.

_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]*$")
_SPECIAL = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~"}


def scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v)
    if _PLAIN.match(s) and s.lower() not in _SPECIAL:
        return s
    return json.dumps(s)


def to_yaml(obj, indent: int = 0) -> list:
    pad = " " * indent
    lines: list = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = scalar(k)
            if isinstance(v, dict) and v:
                lines.append(f"{pad}{key}:")
                lines.extend(to_yaml(v, indent + 2))
            elif isinstance(v, list) and v:
                lines.append(f"{pad}{key}:")
                lines.extend(to_yaml(v, indent + 2))
            elif isinstance(v, (dict, list)):
                lines.append(f"{pad}{key}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                lines.append(f"{pad}{key}: {scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = to_yaml(item, indent + 2)
                lines.append(f"{pad}- {sub[0].lstrip()}")
                lines.extend(sub[1:])
            elif isinstance(item, (dict, list)):
                lines.append(f"{pad}- {'{}' if isinstance(item, dict) else '[]'}")
            else:
                lines.append(f"{pad}- {scalar(item)}")
    else:
        lines.append(pad + scalar(obj))
    return lines


def values_file(model: Model, s: Storage, cls: str, ctx) -> str:
    rel = release(cls)
    api = csi_api_address(s)
    head = [
        f"# {model.lab} democratic-csi release {rel}: rendered from {ctx.profile_file(model)}; edit the spec and run make render",
        f"# helm upgrade --install {rel} democratic-csi -n {CSI_NAMESPACE} -f {VALUES_FILE.format(cls=cls)}, after truenas-setup.py.",
        f"# The driver calls {s.name}'s API on {api}, its address in the data VLAN, as the user"
        f" {(csi_settings(s) or {}).get('user') or 'democratic-csi'}.",
        f"# Its configuration, with the password, is the Secret {config_secret(cls)} in {CSI_NAMESPACE}, which",
        f"# truenas-setup.py writes from bootstrap/{s.name}/setup.json; the chart needs driver.config.driver beside it.",
    ]
    if cls == (csi_settings(s) or {}).get("default_class"):
        head.append("# This is the cluster's default class, a lab choice: the driver's README marks its freenas-api drivers experimental.")
    if cls == "nfs":
        head.append("# NFS serves ReadWriteMany claims; shares are open to the data VLAN only.")
    head.append("# Every image is pinned by digest (spec/versions.yaml); the snapshotter is off until the cluster has the snapshot CRDs.")
    return "\n".join(head + to_yaml(values(model, s, cls))) + "\n"


# --------------------------------------------------------------------------------------------


def render(model: Model, ctx) -> dict:
    out: dict = {}
    tn = truenas_nodes(model)
    for s in model.storage.values():
        if s.product != "truenas":
            ctx.warn(f"storage: {s.name} is {s.product}; its setup file is not rendered yet")
    if len(tn) > 1:
        raise RenderError("storage: one TrueNAS system per lab (the StorageClass names are fixed): "
                          + ", ".join(s.name for s in tn))
    for s in tn:
        out[f"bootstrap/{s.name}/setup.json"] = truenas_setup(model, s, ctx)
        if _csi_enabled(model) and csi_settings(s):
            for c in csi_classes(s):
                out[f"bootstrap/k8s/{VALUES_FILE.format(cls=c)}"] = values_file(model, s, c, ctx)
    return out
