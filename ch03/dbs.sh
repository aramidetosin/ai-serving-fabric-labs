#!/usr/bin/env bash
# ch03/dbs.sh: one PortChannel member on fe-sw1 followed through SONiC's databases (book Chapter 3,
# "SONiC Architecture and Its Databases"), recorded as audits/sfab-ch03_dbs_<UTC>/ with FOLLOWED.txt,
# verdict.txt and one directory a database: proc/, klish/, config/, appl/, state/, counters/ and
# asic/. common/sonic/dbs.sh does the reads; it changes nothing on any device.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init dbs "$@"
# shellcheck source=common/sonic/dbs.sh
. "$SFAB_COMMON/sonic/dbs.sh"
dbs_run
