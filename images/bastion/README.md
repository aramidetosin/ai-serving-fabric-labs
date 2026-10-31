# sfab/bastion

The lab's jump host: it gives access to the private networks and does nothing else. sshd with key-only login, lldpd, and the operator's tools: kubectl, helm and cilium-cli at their pins, dig, openssl and curl. It serves no DNS, no time and no CA (the services hosts and the lab host hold those), has no leg in the BMC VLAN, and holds no standing cluster-admin credential: each operator's kubeconfig there carries a client certificate valid for hours, which the finish stage issues on the init node. `make -C images bastion` builds it (`image.mk`) from `ubuntu:24.04` by digest, the pinned archive snapshot, and the tools' versions and sha256 in `spec/versions.yaml` (`kubernetes.kubectl`, `kubernetes.helm`, `kubernetes.cilium_cli`); a download whose sha256 differs stops the build. The image holds no password, key, lab name or organization name.

## What the topology gives it (render/clab.py)

| Path | From | What |
|---|---|---|
| `/sfab/bootstrap/` (read-only) | `bootstrap/bastion/` | `init.env` (render/host.py) |
| `/shared/ca` (read-only) | `state/shared/ca/` | the lab root (`root.crt`) and the intermediates' certificates, which `sfab-ca` publishes on the lab host (common/ca/) |
| `/sfab/operators` (read-only) | `state/operators/` | each operator's short-lived kubeconfig, `<user>/kubeconfig`, which the finish stage writes |
| `/sfab/authorized_keys` (read-only) | `state/secrets/authorized_keys` | the operator's login keys: the lab key and the deploying user's own |

Nothing else of `state/` reaches it: no CA key, no cluster file, no join token.

## bastion-init.sh (PID 1)

1. IPv6 off for the namespace; resolv.conf, before it waits for anything, as the client's `init.sh` writes it: the search line is always `SEARCH`, the platform's zone, never the one Docker copies from the lab host's own file, and the nameservers are `DNS_SERVERS` (the two resolvers, dns-res1 and dns-res2). Then it waits up to `LINK_WAIT` seconds (600 by default) for eth1 and eth2.
2. `bond0`: 802.3ad over eth1 and eth2, `lacp_rate fast`, `miimon 100`, `layer3+4`, the bastion's address in VLAN 300, and the main default via the firewall. An out-of-band NIC only when the render names one (build A's bastion has none).
3. Management: the default in table 150 behind a rule for the management address; main keeps no management default.
4. TX checksum offload off on eth1, eth2 and bond0.
5. The operator user (`GUEST_USER`, else `admin`): no password, sudo, key-only sshd, no root login.
6. lldpd on the data NICs.
7. Writes `/run/sfab/bastion.ready`, then every 10 s restarts a dead service, trusts the lab root (`CA_ROOT`) once it exists, and installs the operator's kubeconfig when `OPERATOR_DIR/<user>/kubeconfig` appears or changes, for that operator only.

`SIGTERM` stops every service and exits 0, so `docker stop` takes about a second. A setup failure leaves PID 1 idle for `docker exec`. `bastion-init.sh --health` is the image's health check.

## Before sfab/bastion:4

Up to `sfab/bastion:3` the bastion also served the lab's DNS views (BIND), its time (chrony) and its CA (`sfab-ca`), had a leg in the BMC VLAN and held the cluster's admin kubeconfig for the harness. Those moved to the services hosts (images/resolver), the lab host (common/ca/sfab-ca) and the init node (the harness's kubectl, common/lib.sh `K`). What was recorded on that image:

In a sealed container (no network) with the dev/m2 render:

- named answered `llm.tarnwick.example` with 10.20.1.200 from a data address and 10.20.1.210 from an enterprise address; from the enterprise address `k8s-cp1.tarnwick.example` answered 10.20.1.210 (the wildcard) and `-x 10.20.1.11` was NXDOMAIN; a name outside the lab was NXDOMAIN with `aa` from inside and REFUSED from the enterprise LAN; AAAA for a name with only an A record was NOERROR with no answer.
- chronyd served stratum 10 from its local reference with `-x` and without `CAP_SYS_TIME`; `chronyc` as root works only when `/run/chrony` is mode 0750, which bastion-init sets.
- With the spec's kubernetes intermediate as written, kubectl (Go) refused an API server certificate that names the node: `DNS name "k8s-cp1" is not permitted by any constraint`.
