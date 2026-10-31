# sfab/resolver

The lab's DNS and time servers: the platform's authoritative pair `dns-auth1` and `dns-auth2` (BIND, `ROLE=bind-auth`, recursion off, `dns-auth2` a secondary of `dns-auth1` by zone transfers keyed per view with TSIG), its two recursive resolvers `dns-res1` and `dns-res2` (BIND, `ROLE=bind-recursive`, which also serve time with chrony), the enterprise's corporate resolver `ent-dns` (dnsmasq, `ROLE=dnsmasq`), the operator's and the internet's public servers (`bind-auth`) and the upstream time reference `inet-ntp` (chrony alone, with NTS). `make -C images resolver` builds it (`image.mk`) from `alpine:3.20` by digest with BIND, dnsmasq and chrony at the package versions `images.resolver.packages` pins in `spec/versions.yaml`. It takes the client's `init.sh` (the network step) as a named build context, so it exists once in the repo; `sfab-dns` and `sfab-ntp` live here.

## How a resolver starts

- PID 1 is tini running `resolver-run.sh`, which holds the container up.
- The topology runs `/usr/local/sbin/sfab-init.sh` (this directory's `resolver-init.sh`) as the node's exec once the links are attached. It runs the client's network step on `init.env` (the port's address and gateway, or the 802.3ad bond to the pair for the services hosts; the management default in table 150; resolv.conf searching the host's domain; TX checksum offload off; the lab root CA when `CA_ROOT` is set), then, when the node has a DNS role, `sfab-dns start` on the render beside `init.env` (`named.conf` and `zones/`, or `dnsmasq.conf`) with the TSIG keys bound at `/sfab/tsig`, then, when the render holds `chrony.conf`, `sfab-ntp start` (chronyd with `-x`, so it never adjusts the lab host's clock; a reference's NTS key and chain installed from `/sfab/tls`), then writes `/run/sfab/resolver.ready`.
- From then on `resolver-run.sh` starts a server again within 10 s if it stops. `SIGHUP` re-checks and reloads the DNS render (`docker kill -s HUP <resolver>` after `make render`); `SIGTERM` stops the servers and exits.

The role is `ROLE`, else `DNS_ROLE` from `init.env` (render/host.py writes it from the spec's `dns_role`). A node with no role and a `chrony.conf` (the time reference) runs chronyd alone.

## Behavior recorded on the lab host (2026-10-20)

In a sealed container (no network), BIND 9.18.49 and dnsmasq 2.90:

- the operator's public server answered every name in the zone with the public address to a client in its view, refused a name outside the zone, and refused a client outside its view;
- dnsmasq with `local=` for the zone answered A from `address=` and the host records, and AAAA with NOERROR and no answer, for host-record names and wildcard-only names alike; it refused names outside the zone. Without `local=`, dnsmasq 2.90 answered every AAAA in the zone with REFUSED (it forwards a type it holds no record of, and it has no upstream), which a musl client takes as a failure of the whole name. The render therefore writes `local=`.
