#!/usr/bin/env bash
# ch02/matrix.sh: every cell of the population and endpoint matrix, its mode asserted (book Examples
# 2-9 and 2-10; FRAMEWORK.md 4.8), recorded as audits/sfab-ch02_matrix_<UTC>/ with MATRIX.md,
# verdict.txt, requests.tsv, lookups/, requests/, keys/, fw/, routers/ and api-gateway/.
#
# gen/matrix.json is the matrix (Table 2-2) as render/decisions.py computes it from the spec: four
# populations (the staff from the enterprise client, the operator from its client behind its site's
# IPsec router, the nodes from k8s-cp2 in VLAN 100, and an internet host that is not the operator
# from the web client) against eleven endpoints, each cell's mode with the layer that decides it.
# Each cell is tried from the population's own client, by TCP connect from a pinned source port or by
# HTTP request by name through the client's own resolver, never by ping; a model's route is asked
# twice, with its own key and with the other model's (each key, the first of an application caller,
# handed to the client from its Secret through pipes, never printed). common/matrix/matrix.py asserts
# each cell's mode with its evidence: the connect or the status; the traffic log's deny-all-log line
# with its zones and the client's view (a timeout or an error), and for a cell that reaches the
# firewall through the uplink router, the router's route to it; a silent cell's device with its own
# evidence (a router's table without the route, the firewall's discard route, or zone protection's
# strict IP check: the firewall's route back to the source through the tunnel and its drop counter
# over the run); the 404 with no line in the API gateway's log; the 401 with the API gateway's own
# message. The only files it leaves are its own result set's: the clients' copies are removed.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init matrix "$@"
# shellcheck source=common/matrix/matrix.sh
. "$SFAB_COMMON/matrix/matrix.sh"
matrix_run
