"""topo.clab.yml, the containerlab topology of one lab (FRAMEWORK.md section 2.4), and
gen/clab-state.json, what the topology needs on disk and in the environment before a deploy.

Lab-wide: `name` is the lab (sfab-ch03, sfab-ch12m, sfab-m1) and `prefix: __lab-name`, so the
containers are <lab>-<node> and the lab directory is clab-<lab>. The management network is the
build's own, and every node gets a static mgmt-ipv4 from the spec.

Per kind:
- SONiC switches: kind dell_sonic, NUM_NICS from ports.num_nics, CLAB_MGMT_PASSTHROUGH where the
  spec sets it (build A's pair: Management0 on the harness address the stages reach the switch on;
  the keepalive runs on its own link, so the renderer refuses a pair member without passthrough only
  when its keepalive would ride the management VRF), and the KLISH startup file bound at
  /config/startup-config.cfg read-only, and IPv6 off by default in the container's namespace
  (NO_IPV6_SYSCTLS). The switch credentials stay the kind's defaults.
- PA-VM: kind paloalto_panos, the rendered XML as startup-config and QEMU sizing. No USERNAME or
  PASSWORD: containerlab's paloalto_panos kind gives the launcher its default login on its command
  line, and the launcher never reads those two from the environment (the M1 deploy, dev/m1/RESULTS.md,
  problem 4). So the PA-VM keeps the kind's default login, as the switches do, no firewall
  password is generated, and the harness and common/fw read the login from the container's
  launcher arguments.
- TrueNAS: kind generic_vm, the launcher's env, persistence under state/nodes/<n>/persist.
- VM guests (vm-node): kind linux, restart-policy "no" (a guest that powers off stays off),
  /dev/kvm and /dev/net/tun, IPv6 off by default in the container's namespace
  (NO_IPV6_SYSCTLS), the guest's sizing and data NICs in env (and SFAB_NIC_LINK=tc when the spec's
  guest.nic_link is tc), its bootstrap directory, its disk directory, the shared directory and the
  authorized keys (state/secrets/authorized_keys: the lab key and the deploying user's own keys).
- Containers: the bastion and FRR run their own init as PID 1, and both bind the same authorized
  keys for their SSH login; clients, resolvers and the
  registry run the image's init script as the single topology exec, after the links attach. The
  containers cabled to the switches (the bastion's bond, and the services hosts' bonds on the pair)
  also get IPv6 off by default in their namespace (NO_IPV6_SYSCTLS): the init turns it off on its
  NICs, but a veth containerlab moves in before that keeps it, and a switch must never learn a
  container MAC from a router solicitation.
  When their init.env names the lab root CA (render/host.py trusts_lab_ca), they bind
  state/shared/ca read-only at /shared/ca, where sfab-ca publishes root.crt on the lab host; nothing
  else under state/shared reaches them. The bastion binds that and state/operators read-only (each
  operator's short-lived kubeconfig) and nothing else of state/: no CA key, no cluster file. A node
  with a leaf certificate (render/ca.py) binds state/tls/<node> read-only at /sfab/tls; the
  authoritative servers whose views transfer bind state/secrets/tsig read-only at /sfab/tsig (the
  TSIG keys common/bin/secrets.py makes for the names gen/clab-state.json lists under "tsig").

Links name container ethN on both ends. Build A uses no startup-delay; build B boots its
switches in waves of host.boot_batch, startup-delay host.startup_delay_s times the wave.

The topology holds no secret: every credential is a ${SFAB_*} reference or a file under state/.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .. import ports
from ..model import Firewall, Host, Model, Storage, Switch
from . import RenderError
from .host import IPSEC_DIR, LISTEN_SCRIPT, OPERATOR_DIR, TLS_DIR, TSIG_DIR, trusts_lab_ca

SCHEMA = 1

# The PA-VM's QEMU sizing (FRAMEWORK 2.4). The 16.5 GiB host budget covers QEMU's overhead.
FW_QEMU = {"QEMU_CPU": "host", "QEMU_SMP": "8", "QEMU_MEMORY": "16384"}

# Where the images take their files (the contract with images/, see the module docstring).
GUEST_BOOTSTRAP = "/sfab/bootstrap"     # bootstrap/<n>/ read-only: node.env, containerd/, init.env, ...
GUEST_DISK = "/vm"                      # state/nodes/<n>/ : the qcow2 overlay and the NoCloud seed
SHARED = "/shared"                      # state/shared/ : hold-guests, cluster/, ca/
AUTHORIZED_KEYS = "/sfab/authorized_keys"
GUEST_MODELS = "/models"
# The guests' authorized keys: the lab key's public half and the public keys of the user who runs
# make up (~/.ssh/*.pub), which common/bin/secrets.py writes at every preflight.
LAB_PUBKEY = "state/secrets/authorized_keys"
CONTAINER_INIT = "/usr/local/sbin/sfab-init.sh"
TRUENAS_PERSIST = "/persist"
REGISTRY_DATA = "/var/lib/registry"
GUEST_DEVICES = ("/dev/kvm", "/dev/net/tun")
# guest.nic_link, how vm-init.sh joins a VM node's data NICs to their taps: bridge, the default,
# leaves it to the host kernel and renders nothing; tc forces the tc redirect (SFAB_NIC_LINK=tc)
NIC_LINKS = ("bridge", "tc")
# IPv6 off for every device a container gets after it is created: the data veths containerlab
# moves in at deploy take the namespace's default. Only the default matters, and containerlab sets
# net.ipv6.conf.all.disable_ipv6 to 0 on a kind linux node whatever the topology asks (the M1
# deploy's docker inspect), so the topology names only the default (the M1 deploy, dev/m1/RESULTS.md, problems 6, 10 and 11).
# - Guests: vm-init.sh is held (state/shared/hold-guests) while the links already exist; with IPv6
#   on, the veths sent router solicitations from the container's own MACs, which the switches
#   learned. vm-init.sh turns IPv6 off per device again once it runs.
# - Switches: the patched launcher sets the default, then each ethN it lists, as it starts; a veth
#   moved in between its listing and its write kept IPv6 (oob-sw's eth3 in one deploy).
# - The bastion: bastion-init.sh sets the default and every NIC as it starts, which can lose the same
#   race as the switches' launcher.
NO_IPV6_SYSCTLS = {"net.ipv6.conf.default.disable_ipv6": "1"}

# Credentials, by node kind: (USERNAME reference, PASSWORD reference). The switches (dell_sonic)
# and the PA-VM (paloalto_panos) have none: they keep their kinds' default logins.
CREDENTIALS = {
    "truenas": ("SFAB_TRUENAS_USER", "SFAB_TRUENAS_PASSWORD"),
    "ontap": ("SFAB_ONTAP_USER", "SFAB_ONTAP_PASSWORD"),
}



def credential_names() -> list:
    """Every SFAB_ variable a topology can reference (common/bin/secrets.py makes each one)."""
    return sorted({name for pair in CREDENTIALS.values() for name in pair})


# Container kinds whose image runs its init as PID 1 (it waits for its own links).
PID1_INIT = ("bastion", "frr")
# Container kinds whose image init runs as the topology exec.
EXEC_INIT = ("client", "resolver", "registry", "vpngw")


# --------------------------------------------------------------------------------------------
# A small YAML writer for the subset the topology uses. Keys keep the order given; strings are
# quoted whenever a plain scalar could be read as something else.

_PLAIN = re.compile(r"^[A-Za-z0-9_./][A-Za-z0-9_./:@+=-]*$")
_SPECIAL = {"", "~", "null", "true", "false", "yes", "no", "on", "off", "y", "n"}


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def scalar(v, force_quote: bool = False) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v)
    if force_quote or not _PLAIN.match(s) or s.lower() in _SPECIAL or re.match(r"^[0-9.:+-]+$", s) or ": " in s or s.endswith(":"):
        return _quote(s)
    return s


class Q(str):
    """A string always written quoted (containerlab env values are strings)."""


class Flow(list):
    """A list written in flow style, on one line."""


class Noted(dict):
    """A one-line mapping in a list, written with a trailing comment."""

    def __init__(self, d: dict, note: str):
        super().__init__(d)
        self.note = note


def _emit(obj, indent: int, out: list) -> None:
    pad = "  " * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = scalar(k)
            if isinstance(v, (dict, list)) and not isinstance(v, Flow) and v:
                out.append(f"{pad}{key}:")
                _emit(v, indent + 1, out)
            else:
                out.append(f"{pad}{key}: {_inline(v)}")
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, Noted) and len(v) == 1:
                (k, x), = v.items()
                out.append(f"{pad}- {scalar(k)}: {_inline(x)}  # {v.note}")
            elif isinstance(v, dict) and not isinstance(v, Flow):
                first = True
                sub: list = []
                _emit(v, indent + 1, sub)
                for line in sub:
                    if first:
                        out.append(f"{pad}- {line.lstrip()}")
                        first = False
                    else:
                        out.append(line)
            else:
                out.append(f"{pad}- {_inline(v)}")
    else:
        out.append(f"{pad}{_inline(obj)}")


def _inline(v) -> str:
    if isinstance(v, Flow) or (isinstance(v, list) and not v):
        return "[" + ", ".join(_inline(x) for x in v) + "]"
    if isinstance(v, dict) and not v:
        return "{}"
    if isinstance(v, Q):
        return scalar(v, force_quote=True)
    return scalar(v)


def to_yaml(obj, header: list | None = None) -> str:
    out = [f"# {h}" if h else "#" for h in (header or [])]
    _emit(obj, 0, out)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------
# The topology


def boot_waves(names, batch: int, delay_s: int) -> dict:
    """startup-delay per switch for a wave boot: the first `batch` switches start at once, the
    next `batch` after delay_s, and so on. Switches in wave 0 get no startup-delay."""
    if batch <= 0:
        raise RenderError(f"host.boot_batch must be positive, not {batch}")
    out = {}
    for i, n in enumerate(names):
        w = i // batch
        if w:
            out[n] = int(delay_s) * w
    return out


def _env(d: dict) -> dict:
    return {k: Q(str(v)) for k, v in sorted(d.items())}


def _ref(name: str) -> str:
    return "${" + name + "}"


def _rel_to_root(ctx, model: Model, sub: str) -> str:
    """A repo path relative to the directory holding topo.clab.yml (containerlab resolves bind
    paths from there): the lab directory, or its variants/<key>/ directory."""
    base = Path(ctx.labdir)
    if model.variant:
        base = base / "variants" / model.variant
    return Path(os.path.relpath(Path(ctx.root) / sub, base)).as_posix()


class _State:
    def __init__(self) -> None:
        self.dirs: set = set()
        self.files: set = set()
        self.env: set = set()
        self.bootstrap: set = set()
        self.tsig: list = []
        self.ipsec: list = []


def _switch(model: Model, sw: Switch, st: _State) -> dict:
    n = ports.num_nics(sw)
    if n != sw.num_nics:
        raise RenderError(f"{sw.name}: NUM_NICS {sw.num_nics} in the model, {n} from its ports")
    env = {"NUM_NICS": n}
    if sw.passthrough:
        env["CLAB_MGMT_PASSTHROUGH"] = "true"
    node = {"kind": sw.clab_kind, "image": sw.image, "mgmt-ipv4": sw.mgmt,
            "sysctls": {k: Q(v) for k, v in NO_IPV6_SYSCTLS.items()}, "env": _env(env),
            "binds": [f"bootstrap/{sw.name}/startup-config.cfg:/config/startup-config.cfg:ro"]}
    return node


def _firewall(model: Model, fw: Firewall, st: _State) -> dict:
    # QEMU sizing only: the launcher takes the kind's default login from its command line.
    env = dict(FW_QEMU)
    return {"kind": fw.clab_kind, "image": fw.image, "mgmt-ipv4": fw.mgmt,
            "startup-config": f"bootstrap/{fw.name}/startup-config.xml", "env": _env(env)}


def _storage(model: Model, s: Storage, st: _State, ctx) -> dict:
    user, pw = CREDENTIALS.get(s.product, CREDENTIALS.get(s.kind, ("SFAB_STORAGE_USER", "SFAB_STORAGE_PASSWORD")))
    st.env.update((user, pw))
    persist = f"state/nodes/{s.name}/persist"
    st.dirs.add(persist)
    env = {"USERNAME": _ref(user), "PASSWORD": _ref(pw)}
    if s.product == "truenas":
        cfg = s.settings or {}
        env.update({
            "TRUENAS_RAM": int(round(s.budget.mem_gib * 1024)),
            "TRUENAS_SMP": int(s.budget.vcpus),
            "TRUENAS_DATA_DISKS": cfg.get("data_disks", 4),
            "TRUENAS_DATA_DISK_SIZE": cfg.get("data_disk_size", "100G"),
            "TRUENAS_POOL": cfg.get("pool", "tank"),
        })
        if cfg.get("arc_max_mb") is not None:
            env["TRUENAS_ARC_MAX_MB"] = cfg["arc_max_mb"]
    else:
        ctx.warn(f"{s.name}: the {s.product} launcher's env is not settled; only its credentials are rendered")
    return {"kind": s.clab_kind, "image": s.image, "mgmt-ipv4": s.mgmt, "env": _env(env),
            "binds": [f"{persist}:{TRUENAS_PERSIST}"]}


def _guest(model: Model, h: Host, st: _State, ctx=None) -> dict:
    disk = f"state/nodes/{h.name}"
    st.dirs.update((disk, "state/shared"))
    st.files.add(LAB_PUBKEY)
    st.bootstrap.add(h.name)
    gc = model.common.get("guest") or {}
    env = {
        "SFAB_LAB": model.lab,
        "SFAB_NODE": h.name,
        "VM_MEMORY_MB": int(round(h.budget.mem_gib * 1024)),
        "VM_SMP": int(h.budget.vcpus),
        "VM_DISK_GIB": int(h.disk_gib),
        "VM_NICS": " ".join(h.eths),
        "VM_TX_OFF": "1" if gc.get("tx_offload_off", True) else "0",
    }
    link = str(gc.get("nic_link", "bridge"))
    if link not in NIC_LINKS:
        raise RenderError(f"guest.nic_link is {link!r}: it must be one of {', '.join(NIC_LINKS)}")
    if link != "bridge":
        env["SFAB_NIC_LINK"] = link
    return {
        "kind": h.clab_kind, "image": h.image, "mgmt-ipv4": h.mgmt,
        "restart-policy": Q("no"),
        "devices": Flow(GUEST_DEVICES),
        "sysctls": {k: Q(v) for k, v in NO_IPV6_SYSCTLS.items()},
        "env": _env(env),
        "binds": [
            f"bootstrap/{h.name}:{GUEST_BOOTSTRAP}:ro",
            f"{disk}:{GUEST_DISK}",
            f"state/shared:{SHARED}",
            f"{LAB_PUBKEY}:{AUTHORIZED_KEYS}:ro",
        ] + _models_bind(ctx, model, h),
    }


def _models_bind(ctx, model: Model, h: Host) -> list:
    """A GPU node that runs a model server: the models directory (serving.weights.dir, relative to
    the repository root), read-only at /models, which vm-init.sh exports to the guest."""
    from .k8s import serving_settings, weights_nodes  # noqa: PLC0415

    if ctx is None or h.name not in weights_nodes(model):
        return []
    return [f"{_rel_to_root(ctx, model, str(serving_settings(model)['weights']['dir']))}:{GUEST_MODELS}:ro"]


def _container(model: Model, h: Host, st: _State, ctx) -> dict:
    from .ca import TLS_STATE, leaf_of  # noqa: PLC0415
    from .dns import tsig_keys, tsig_servers  # noqa: PLC0415

    st.bootstrap.add(h.name)
    env = {"SFAB_LAB": model.lab, "SFAB_NODE": h.name}
    binds = [f"bootstrap/{h.name}:{GUEST_BOOTSTRAP}:ro"]
    trusts = trusts_lab_ca(model)
    if h.kind == "bastion":
        st.files.add(LAB_PUBKEY)
        binds.append(f"{LAB_PUBKEY}:{AUTHORIZED_KEYS}:ro")
        if model.k8s is not None:
            st.dirs.add("state/operators")
            binds.append(f"state/operators:{OPERATOR_DIR}:ro")
    if h.kind in ("frr", "vpngw"):
        st.files.add(LAB_PUBKEY)
        binds.append(f"{LAB_PUBKEY}:{AUTHORIZED_KEYS}:ro")
    if h.kind == "registry":
        binds.append(f"{_rel_to_root(ctx, model, 'images/registry/data')}:{REGISTRY_DATA}:ro")
    if (h.kind in EXEC_INIT or h.kind == "bastion") and trusts:
        st.dirs.add("state/shared/ca")
        binds.append(f"state/shared/ca:{SHARED}/ca:ro")
    if trusts and leaf_of(model, h.name) is not None:
        st.dirs.add(f"{TLS_STATE}/{h.name}")
        binds.append(f"{TLS_STATE}/{h.name}:{TLS_DIR}:ro")
    if h.name in tsig_servers(model):
        st.tsig = tsig_keys(model)
        st.files.update(f"state/secrets/tsig/{k}.key" for k in st.tsig)
        binds.append(f"state/secrets/tsig:{TSIG_DIR}:ro")
    if h.kind == "vpngw":
        from .panos import vpn_psks  # noqa: PLC0415

        names = vpn_psks(model)
        if not names:
            raise RenderError(f"{h.name}: a VPN router needs the firewall's tunnel to it in the lab")
        st.ipsec = sorted(set(st.ipsec) | set(names))
        st.files.update(f"state/secrets/ipsec/{k}.psk" for k in names)
        binds.append(f"state/secrets/ipsec:{IPSEC_DIR}:ro")
    node = {"kind": h.clab_kind, "image": h.image, "mgmt-ipv4": h.mgmt}
    if h.kind == "bastion" or h.bond is not None:
        node["sysctls"] = {k: Q(v) for k, v in NO_IPV6_SYSCTLS.items()}
    node.update({"env": _env(env), "binds": binds})
    if h.kind in EXEC_INIT:
        node["exec"] = [CONTAINER_INIT]
        if (h.props or {}).get("listen"):
            # a plain TCP listener on the host's ports (bootstrap/<node>/listen.py, render/host.py)
            node["exec"].append(f"sh -c 'nohup python3 {GUEST_BOOTSTRAP}/{LISTEN_SCRIPT} >/dev/null 2>&1 &'")
    elif h.kind not in PID1_INIT:
        raise RenderError(f"{h.name}: no topology rule for host kind {h.kind!r}")
    return node


def _check_pairs(model: Model) -> None:
    for pair in model.pairs.values():
        present = [m for m in pair.members if m in model.nodes]
        if not present:
            continue
        if len(present) != 2:
            raise RenderError(f"pair {pair.name}: only {present} in the lab; an MCLAG pair deploys whole")
        for m in present:
            sw = model.nodes[m]
            if not isinstance(sw, Switch) or (sw.keepalive is None and not sw.passthrough):
                raise RenderError(f"pair {pair.name}: {m} lacks CLAB_MGMT_PASSTHROUGH; the keepalive in VRF {pair.session_vrf} needs the real management address on both members")


def topology(model: Model, ctx) -> str:
    """The text of topo.clab.yml."""
    return build(model, ctx)[0]


def clab_state(model: Model, ctx) -> dict:
    """What the topology needs before a deploy (gen/clab-state.json): the state/ directories and
    files its binds name, the SFAB_ environment references it holds, the bootstrap directories
    it binds, and the worker count for `containerlab deploy --max-workers`."""
    return build(model, ctx)[1]


def build(model: Model, ctx) -> tuple:
    """(topo.clab.yml text, the gen/clab-state.json data)."""
    _check_pairs(model)
    st = _State()
    nodes: dict = {}
    for name, n in model.nodes.items():
        if n.pending:
            continue
        if isinstance(n, Switch):
            nodes[name] = _switch(model, n, st)
        elif isinstance(n, Firewall):
            nodes[name] = _firewall(model, n, st)
        elif isinstance(n, Storage):
            nodes[name] = _storage(model, n, st, ctx)
        elif isinstance(n, Host) and n.kind == "vm-node":
            nodes[name] = _guest(model, n, st, ctx)
        elif isinstance(n, Host):
            nodes[name] = _container(model, n, st, ctx)
        else:
            raise RenderError(f"{name}: no topology rule for kind {n.kind!r}")
    if model.build == "B":
        hc = model.common.get("host") or {}
        waves = boot_waves([s for s in model.switches if s in nodes], int(hc.get("boot_batch", 8)), int(hc.get("startup_delay_s", 180)))
        for sw, d in waves.items():
            nodes[sw]["startup-delay"] = d
    links = []
    for l in model.links:
        if l.a.node not in nodes or l.b.node not in nodes:
            raise RenderError(f"link {l.id} ends on a node the topology does not deploy")
        sw_ends = [e for e in (l.a, l.b) if isinstance(model.nodes.get(e.node), Switch)]
        note = ", ".join([l.attachment] + [f"{e.node} {ports.native(e.eth)}" for e in sw_ends])
        links.append(Noted({"endpoints": Flow([Q(str(l.a)), Q(str(l.b))])}, note))
    ch = model.meta.chapter
    chapter = ctx.rel(ch.path) if ch is not None and getattr(ch, "path", None) else "chapter.yaml"
    header = [
        f"{model.lab}: rendered from {ctx.profile_file(model)} and {chapter}; edit the spec and run make render.",
        f"Build {model.build}, state {model.state}, step {model.step}. Containers are {model.prefix}<node>, the lab directory {model.clabdir}/.",
    ]
    if st.env:
        header += [
            "Credentials are SFAB_ environment references: containerlab expands them from the environment,",
            "which the up stage loads from state/secrets.env. No secret is written here.",
        ]
    else:
        header += [
            "No credential is referenced here: the nodes that log in with a password keep their kinds'",
            "default logins, which the harness reads from each container. No secret is written here.",
        ]
    mg = {"network": model.mgmt.network}
    if model.mgmt.bridge:
        mg["bridge"] = model.mgmt.bridge
    mg["ipv4-subnet"] = model.mgmt.subnet
    mg["ipv4-gw"] = model.mgmt.gw
    doc = {"name": model.lab, "prefix": "__lab-name", "mgmt": mg, "topology": {"nodes": nodes, "links": links}}
    text = to_yaml(doc, header)
    state = {
        "schema": SCHEMA,
        "lab": model.lab,
        "dirs": sorted(st.dirs),
        "files": sorted(st.files),
        "env": sorted(st.env),
        "bootstrap_dirs": sorted(f"bootstrap/{b}" for b in st.bootstrap),
        "max_workers": len(nodes),
        "tsig": sorted(st.tsig),
        "ipsec": sorted(st.ipsec),
    }
    return text, state


def render(model: Model, ctx) -> dict:
    text, state = build(model, ctx)
    return {"topo.clab.yml": text, "gen/clab-state.json": json.dumps(state, indent=2, sort_keys=True) + "\n"}
