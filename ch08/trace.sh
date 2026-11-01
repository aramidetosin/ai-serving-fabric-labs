#!/usr/bin/env bash
# ch08/trace.sh: the keyed trace (FRAMEWORK.md 4.5), recorded as audits/sfab-ch08_trace_<UTC>/ with
# TRACE.md, verdict.txt, cluster/, request/ and captures/.
#
# Chapter 7's keyed serving trace from k8s-cp2, a node of the cluster (chapter.yaml trace.serving,
# common/trace/lib-servetrace.sh): the node's own datapath answers every Gateway VIP, so its requests
# name the VIP with curl --resolve and its own ports are captured to show no SYN to the VIP leaves it.
# One chat completion on staff's path through the users' Gateway with staff's own key (helpdesk's, a
# 0600 header file in the guest, handed over ssh's standard input and never printed), the API
# gateway's and the router's cluster interfaces captured whole with every Authorization value
# replaced by its keyed mark: the caller's key at the first hop, the router's master key at the
# second, the backend key at the third. Then the same key and path through the internet Gateway,
# whose route set carries chat alone: its 404, and no request for it at any API gateway pod. Then an
# admin hostname on the internet Gateway: its 404. Changes nothing on any device; every process it
# starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-servetrace.sh
. "$SFAB_COMMON/trace/lib-servetrace.sh"
servetrace_run
