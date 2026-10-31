#!/usr/bin/env bash
# ch07/trace.sh: the keyed trace (book Examples 7-8, 7-9 and 7-12; FRAMEWORK.md 4.5), recorded as
# audits/sfab-ch07_trace_<UTC>/ with TRACE.md, verdict.txt, cluster/, request/ and captures/.
#
# Chapter 6's serving trace, keyed: one chat completion from the enterprise client to chat through
# the users' Gateway, with chat's key (the batch caller's, handed to the client from its Secret as a
# 0600 header file, never printed) and its source port pinned, after one warm-up request. The API
# gateway's and the router's cluster interfaces are captured whole, so the HTTP request each
# in-cluster hop carried is in the capture; each pcap leaves its guest only on a pipe through
# common/trace/keyscrub.py, which replaces every Authorization value by its keyed mark under the
# lab's redaction key, and only the scrubbed pcap and its decodes reach the set. request/key.txt,
# master-key.txt and backend-key.txt name the caller's key, the router's master key and the backend
# key by field, fingerprint and mark, read through pipes from their Secrets. The judge reads the
# marks hop by hop: the caller's key from the Gateway's proxy to the API gateway pod, the router's
# master key in its place from the API gateway to the router, the backend key from the router to the
# server, and every Authorization value in the captures a mark. Then one request from the same
# client, with no key, to admin.ai.tarnwick.example, which the users' Gateway does not carry (the
# enterprise view publishes no admin name, so the request is pinned to the users' VIP): the
# Gateway's 404, and no API gateway pod sees it. The rest of chapter 6's judgment holds: the copy,
# its RPC on the rail and the rail switch ports. Changes nothing on any device; every process it
# starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-servetrace.sh
. "$SFAB_COMMON/trace/lib-servetrace.sh"
servetrace_run
