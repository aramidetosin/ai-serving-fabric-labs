#!/usr/bin/env bash
# ch11/trace.sh: the keyed trace (FRAMEWORK.md 4.5), recorded as audits/sfab-ch11_trace_<UTC>/ with
# TRACE.md, verdict.txt, cluster/, request/ and captures/.
#
# Chapter 7's serving trace, keyed (chapter.yaml trace.serving): one request from the staff client to
# staff's path through the users' Gateway with helpdesk's key (a 0600 header file, never printed), the
# API gateway's and the router's cluster interfaces captured whole with every Authorization value
# replaced by its keyed mark, then an admin hostname the users' Gateway does not carry, answered 404
# there, which no API gateway pod sees. Part III's own trace forms land with
# the record stage. Changes nothing on any device; every process it starts it
# stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-servetrace.sh
. "$SFAB_COMMON/trace/lib-servetrace.sh"
servetrace_run
