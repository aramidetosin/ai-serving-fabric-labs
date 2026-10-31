#!/usr/bin/env bash
# ch04/trace.sh: the firewall trace (book Examples 4-6, 4-7 and 4-11; FRAMEWORK.md 4.5), recorded as
# audits/sfab-ch04_trace_<UTC>/ with TRACE.md, verdict.txt, sessions/ and pull/.
#
# Proof moves from probes to state. One HTTPS request from each side of the firewall, each held open
# after its reply: the enterprise client to the users' VIP (no translation), and the operator's
# client to the internal Gateway's VIP through the IPsec tunnel from its site router into zone
# operator-vpn (no translation; nothing is published on the public address). While each is held, its
# session as show session all lists it and as show session id prints it (zones, the destination, the
# security rule and no NAT rule); after the client closes it, its traffic log line. Then k8s-gpu2
# pulls the node helm image through its registry mirror, captured on both ae1 legs and on the
# uplink, where internet-snat has rewritten its source to the public address. The plan is
# chapter.yaml's trace block, rendered to gen/trace.json. Changes nothing on any device except the
# image pulled on k8s-gpu2 and removed again; every process it starts it stops
# (common/trace/lib-fwtrace.sh).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-fwtrace.sh
. "$SFAB_COMMON/trace/lib-fwtrace.sh"
fwtrace_run
