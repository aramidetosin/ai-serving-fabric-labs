#!/usr/bin/env bash
# ch11/trace.sh: Part III's trace (FRAMEWORK.md 4.5), recorded as audits/sfab-ch11_trace_<UTC>/ with
# TRACE.md, verdict.txt and captures/ (common/trace/lib-p3trace.sh, judged by common/trace/p3trace.py).
#
# The capture ladder (chapter.yaml trace.ladder): every population of the matrix connects to each
# Gateway's VIP, a forbidden cell three times from its own source ports, while every rung captures
# (the ISP router's link, the staff's firewall port, both legs, the pair's ports facing the ingress
# nodes, each ingress node's VLAN 110 unit). A warm-up connect a population first; the pair's ports
# facing each lease holder read from the MAC tables by the holder's MAC. Per rung, each flow's SYNs by
# distinct sequence number, and each forbidden flow's tally past the device that refuses it, zero.
# Changes nothing on any device; every process it starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-p3trace.sh
. "$SFAB_COMMON/trace/lib-p3trace.sh"
p3trace_run
