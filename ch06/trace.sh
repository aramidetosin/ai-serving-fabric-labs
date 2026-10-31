#!/usr/bin/env bash
# ch06/trace.sh: the serving trace (book Examples 6-5 and 6-8; FRAMEWORK.md 4.5), recorded as
# audits/sfab-ch06_trace_<UTC>/ with TRACE.md, verdict.txt, cluster/, request/ and captures/.
#
# One chat completion from the enterprise client to the model chat through the users' Gateway, with
# chat's key (the batch caller's, handed to the client from its Secret as a 0600 header file, never
# printed) and its source port pinned, after one warm-up request, pinned to chat's copy c (copy: c
# in chapter.yaml): the router picks the copy, so the trace sends the request again, its source port
# one higher each time and a miss's captures discarded, until chat-c's server took it. Captured for
# that request alone: the ingress node holding the users' VIP's lease (bond0, port 443), every API
# gateway pod and every router pod on its cluster interface, chat's three servers on their cluster
# interface and their rail attachment, its four workers on their rail attachment, and the rail
# switch ports facing each copy's nodes on its rail. The judge follows the request through each hop
# by the addresses each sends to: the API gateway pod that took it, the router pod it went to, the
# server the router's Service picked, and that server's RPC to its workers on rail 7, across
# rail-sw1 for the worker on the other node and inside the node for the one beside it, while chat's
# node-local copies a and b carry none. A pod's cluster interface is captured at 66 bytes a frame,
# so no capture holds an HTTP header. The plan is gen/trace.json; the judgment and TRACE.md are
# common/trace/servetrace.py's. Changes nothing on any device; every process it starts it stops
# (common/trace/lib-servetrace.sh).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-servetrace.sh
. "$SFAB_COMMON/trace/lib-servetrace.sh"
servetrace_run
