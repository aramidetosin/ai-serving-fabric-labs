# sfab/frr

The router every build uses: build A's uplink router (and from chapter 9 its ISP router), build B's carrier from chapter 17. It is FRR 10.5.4 from the project's own image, `quay.io/frrouting/frr:10.5.4`, pinned by digest in `spec/versions.yaml` (`images.frr_upstream`), plus openssh-server, tcpdump, ethtool and sudo, baked in so nothing is fetched at boot.

```
make -C images frr        # sfab/frr:10.5.4-3; rebuilt when a file here is newer than the image
```

## What the topology gives it

`render/clab.py` binds `bootstrap/<router>/` read-only at `/sfab/bootstrap`. `render/frr.py` writes four files there:

| File | Content |
|---|---|
| `frr.conf` | the whole configuration: hostname, the static routes from the spec, one block per wired data port with its description and address |
| `daemons` | zebra, mgmtd and staticd (always started); every other daemon `no` until the spec gives a router a routing protocol |
| `vtysh.conf` | `service integrated-vtysh-config` |
| `init.env` | what `frr-init.sh` needs before FRR starts (below) |

The keys the topology binds at `/sfab/authorized_keys` (the lab key and the deploying user's own) let the login user, `GUEST_USER` (`admin` by default), in over SSH. Without them sshd still runs, and `docker exec <container> vtysh` is the way in (the harness's `FR` runner uses it).

## How it starts

PID 1 is tini, which runs `frr-init.sh`, which then hands over to FRR's own `docker-start` (watchfrr):

1. It waits up to `LINK_WAIT_S` (180 s) for every port in `IFACES` and `TX_OFF`, since containerlab attaches the links after the container starts.
2. It creates the VRF `MGMT_VRF` (`mgmt`, table `MGMT_TABLE`, 150), enslaves the management port eth0 to it and puts the management default route there. The main table then holds only the lab's routes: a packet for an address the router has no route for is answered with ICMP net unreachable, and never leaves through the management network.
3. It turns IPv4 forwarding on and rp_filter off (a router's return path may use another port); on a carrier router it also opens the MPLS label space and sets `net.mpls.conf.<port>.input=1` on the core ports only (`CORE_IFS`), and creates the customer VRFs in `VRFS`.
4. It brings each data port up at its MTU (`ETH<n>_MTU`). zebra has no MTU command for a kernel interface, so the MTU lives here, not in `frr.conf`.
5. It turns TX checksum offload off on every port in `TX_OFF`.
6. It writes resolv.conf's search line as `SEARCH`, the lab's domain, never the one Docker copies from the lab host's own file, and keeps Docker's nameserver and options lines (`DNS_SERVERS` and `RESOLV_OPTIONS` replace them when `init.env` sets them).
7. It links `/etc/frr/frr.conf`, `daemons` and `vtysh.conf` to the bound files, and caps the open-file limit at 100000 (FRR warns at start about the container's far larger default).
8. It starts sshd for `GUEST_USER` (key only, no root, no password) listening in the management VRF only (`ListenAddress 0.0.0.0 rdomain mgmt`), so the data ports never answer on port 22. Host keys are made in each container.

watchfrr then starts the daemons and applies `frr.conf` with `vtysh -b`. The healthcheck is `vtysh -c 'show version'`.

`SFAB_DRY_RUN=1 frr-init.sh` prints every change instead of making it, as if nothing existed yet, and does not start FRR. `SFAB_INIT_ENV` names another init.env.

## The render stays the configuration

The bound files are read-only, so a `write memory` cannot change the render. vtysh does not fail either: it moves the `frr.conf` link aside as `frr.conf.sav` and writes a copy in the container, which the next start of the container replaces with the link again. `sfab-frr-restore` handles a running router:

```
docker exec <router> sfab-frr-restore check     # exit 0: running = render; exit 3: prints the lines FRR would add or remove
docker exec <router> sfab-frr-restore restore   # links the render again and reloads it into the running daemons, then checks
```

Both use FRR's own `frr-reload.py`. `restore` reloads through the `/etc/frr/frr.conf` link, because given any other path frr-reload.py ends with a `write memory` of its own.

## init.env

One header comment line, then `KEY=value` lines sorted by key (the format of `render/host.py`'s env files).

| Key | Meaning |
|---|---|
| `NODE_NAME`, `NODE_KIND`, `NODE_ROLE`, `LAB`, `DOMAIN`, `FQDN` | identity, for the log |
| `MGMT_IF`, `MGMT_ADDR`, `MGMT_GW`, `MGMT_VRF`, `MGMT_TABLE` | the management port, its address and gateway, and the VRF and table it moves into |
| `IFACES` | the data ports wired in this lab |
| `ETH<n>_MTU` | a data port's MTU, when the spec sets one |
| `IP_FORWARD`, `RP_FILTER` | 1 and 0 |
| `TX_OFF` | the ports with TX checksum offload off |
| `LINK_WAIT_S` | how long to wait for the links |
| `GUEST_USER` | the user sshd lets in |
| `SEARCH` | the lab's domain, resolv.conf's search line; `DNS_SERVERS` and `RESOLV_OPTIONS` too if a router ever has a resolver in the lab |
| `CORE_IFS`, `MPLS_LABELS`, `VRFS` | build B's carrier only: MPLS core ports, the label space, and customer VRFs as `name,table,port+port` items |
