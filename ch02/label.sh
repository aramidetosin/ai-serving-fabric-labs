#!/usr/bin/env bash
# ch02/label.sh: the live object behind every row of the decision table (book Examples 2-5 to 2-8;
# FRAMEWORK.md 4.8), recorded as audits/sfab-ch02_label_<UTC>/ with LABELS.md, verdict.txt and one
# directory a row: view/, fw/, routing/, routeset/, key/, placement/ and forwarding/.
#
# gen/decisions.json is the decision table (Table 2-1) as render/decisions.py resolves it from the
# spec, with the objects of this lab that implement each row and the decision id each carries. For
# each row it reads the live object: the population's own lookup and the zone file's entry, the
# firewall's routing table and its NAT and security rulebases in order with each rule's description,
# the uplink router's static routes with their comment lines, every HTTPRoute with its labels, the
# API gateway's consumer groups and one pod's composed consumers, the placement table with the pods'
# labels and the rail attachments' annotations; then each switch's delivered startup file, labelled
# forwarding only, and its empty show ip route. common/matrix/label.py names each object with its
# label. It changes nothing on any device, and no file it writes holds a key.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init label "$@"
# shellcheck source=common/matrix/label.sh
. "$SFAB_COMMON/matrix/label.sh"
label_run
