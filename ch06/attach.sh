#!/usr/bin/env bash
# ch06/attach.sh: chat-c-server-0's two networks (book Chapter 6, "Rail-Aware Model Placement"),
# recorded as audits/sfab-ch06_attach_<UTC>/ with FOLLOWED.txt, verdict.txt and one directory a
# view: k8s/ (the pod and its network-status annotation), node/ (its route table, read on its node),
# services/ (the EndpointSlices of the Services that select it), dns/ (a Service's cluster DNS
# answer from inside the pod) and switch/ (rail-sw1's MAC table). common/reads/attach.sh does the
# reads; it changes nothing in the cluster or on any device.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init attach "$@"
# shellcheck source=common/reads/attach.sh
. "$SFAB_COMMON/reads/attach.sh"
attach_run
