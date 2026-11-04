#!/usr/bin/env bash
# fw-api.sh: live PAN-OS configuration through the XML API, for breaks, heals and reads.
#
#   fw-api.sh [--lab DIR] get <xpath>                     the candidate configuration at xpath
#   fw-api.sh [--lab DIR] show <xpath>                    the running configuration at xpath
#   fw-api.sh [--lab DIR] set <xpath> <element>           add the element under xpath (merged)
#   fw-api.sh [--lab DIR] edit <xpath> <element>          replace the node at xpath with the element
#   fw-api.sh [--lab DIR] set-file <xpath> <file>         as set, the element read from a file (a 0600
#                                                         file for one holding a key: never on a command line)
#   fw-api.sh [--lab DIR] del <xpath>                     delete the node at xpath
#   fw-api.sh [--lab DIR] move <rule xpath> [WHERE [DST]] WHERE is before, after, top or bottom
#   fw-api.sh [--lab DIR] op '<xml command>'              an operational command in its XML form
#   fw-api.sh [--lab DIR] commit [DESCRIPTION]            commit the candidate and wait for the job
#   fw-api.sh [--lab DIR] order [XML]                     running rule order equals the rendered file's?
#   fw-api.sh [--lab DIR] export-pcap FILE OUT            a packet-diag capture file, saved as OUT
#
# export-pcap fetches one file the dataplane's packet-diag capture wrote (type=export,
# category=filter-pcap), chapter 4's drop-stage capture; OUT must start with the pcap magic, or the
# firewall's answer is printed instead and the status is 1.
# order reads the running vsys1 rulebase and compares the security and NAT rule names, in order,
# with XML (default DIR/bootstrap/fw/startup-config.xml): the check enforced.txt cannot make.
# move defaults to `before deny-all-log`, the place every added rule belongs. An element is the
# XML that sfab.render.panos builds for that xpath (rule(), dnat(), snat()), so what a break or
# heal applies live is what the next deploy boots. Why the API: the PAN-OS 12.1.2 CLI refuses set
# syntax for static routes, and the API takes the renderer's own XML.
#
# DIR, the inventory and SFAB_FW_HOST work as in panos.sh; SFAB_FW_API overrides the whole API
# URL (default https://<the firewall's management address>/api/).
#
# Credentials come from panos.sh's sources in the same order (SFAB_FW_PASSWORD when the operator
# exports it as an override, then the --username and --password the firewall container's launcher
# was given, the paloalto_panos kind's default login); a source the firewall refuses falls
# through to the next. One keygen per run: the password reaches curl on its standard input and
# the key sits in a 0600 header file sent as X-PAN-KEY, so neither is ever on a command line, and
# neither is printed. Answers are printed with phash, password and key elements hidden. This
# script writes no transcript: keyed requests stay out of evidence.
#
# Exit status: 0 success; 1 the firewall answered with an error, or a commit failed; 2 usage;
# 5 no credential source taken.

set -euo pipefail

FWA_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=panos.sh
. "$FWA_HERE/panos.sh"

FWA_HDR=""
FWA_URL=""
FWA_BUSY='auto-commit not yet finished|commit is in progress|another commit|is currently in progress|pending jobs|commit job was not queued'

fwa_cleanup() {
    if [[ -n "$FWA_HDR" ]]; then rm -f "$FWA_HDR"; fi
}
trap fwa_cleanup EXIT

fwa_usage() {
    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

# fwa_export_pcap FILE OUT: a packet-diag capture file, binary, into OUT
fwa_export_pcap() {
    local file="$1" out="$2" magic
    curl -sk -m "${FWA_TIMEOUT:-60}" -H @"$FWA_HDR" --data-urlencode type=export --data-urlencode category=filter-pcap \
        --data-urlencode "from=$file" -o "$out" "$FWA_URL" || true
    magic="$(head -c 4 "$out" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    case "$magic" in
        d4c3b2a1 | a1b2c3d4 | 4d3cb2a1 | a1b23c4d | 0a0d0d0a)
            echo "export-pcap: $file saved ($(wc -c <"$out" | tr -d ' ') bytes)"
            return 0
            ;;
    esac
    echo "export-pcap: $file not exported: $(head -c 300 "$out" 2>/dev/null | fwa_hide | tr '\n' ' ')"
    return 1
}

# fwa_xml FIELD: one field of the API answer on stdin.
fwa_xml() {
    python3 -c '
import sys
import xml.etree.ElementTree as ET
f = sys.argv[1]
try:
    e = ET.fromstring(sys.stdin.buffer.read())
except ET.ParseError:
    print("unparsable" if f == "status" else "")
    sys.exit(0)
def t(x):
    return " ".join("".join(x.itertext()).split()) if x is not None else ""
job = e.find(".//job")
if f == "status":
    print(e.get("status") or "")
elif f == "code":
    print(e.get("code") or "")
elif f == "msg":
    print(t(e.find(".//msg")) or t(e))
elif f == "key":
    print(t(e.find(".//key")))
elif f == "job":
    print(t(job.find("id")) if job is not None and job.find("id") is not None else t(job))
elif f == "jobdetails":
    # one <line> per message: joined with "; ", so the lines stay apart on one line
    d = job.find("details") if job is not None else None
    ls = [t(x) for x in d.iter("line")] if d is not None else []
    print("; ".join(x for x in ls if x) if ls else t(d))
elif f in ("jobstatus", "jobresult"):
    print(t(job.find(f[3:])) if job is not None else "")
' "$1"
}

# fwa_hide: secret elements of an answer replaced, for printing.
fwa_hide() {
    sed -E 's#<(phash|password|private-key|key|secret|passphrase)>[^<]*</(phash|password|private-key|key|secret|passphrase)>#<\1>hidden</\1>#g'
}

fwa_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' <<<"$1"
}

# fwa_keygen: an API key from the first credential source the firewall takes, into FWA_HDR.
fwa_keygen() {
    local src resp key answered=0 tried=0
    while IFS= read -r src; do
        pan_cred "$src" || continue
        tried=1
        resp="$(printf '%s' "$PAN_PASS" | curl -sk -m 30 --data-urlencode type=keygen \
            --data-urlencode "user=$PAN_USER" --data-urlencode "password@-" "$FWA_URL" || true)"
        PAN_PASS=""
        [[ -n "$resp" ]] && answered=1
        key="$(fwa_xml key <<<"$resp")"
        if [[ -n "$key" ]]; then
            FWA_HDR="$(mktemp)"
            chmod 600 "$FWA_HDR"
            printf 'X-PAN-KEY: %s\n' "$key" >"$FWA_HDR"
            key=""
            # shellcheck disable=SC2034  # read by pan_sources in panos.sh
            PAN_SRC="$src"
            return 0
        fi
    done < <(pan_sources)
    if [[ "$tried" == 0 ]]; then
        pan_err "no credential source holds a password (SFAB_FW_PASSWORD, the container's launcher arguments)"
        return 5
    fi
    if [[ "$answered" == 0 ]]; then
        pan_err "the firewall API at ${FWA_URL%%/api/*} does not answer"
        return 1
    fi
    pan_err "the firewall took no credential source (SFAB_FW_PASSWORD, the container's launcher arguments)"
    return 5
}

fwa_api() {
    curl -sk -m "${FWA_TIMEOUT:-60}" -H @"$FWA_HDR" "$@" "$FWA_URL"
}

# fwa_result: print status and message of the answer on stdin; status 1 unless it is success.
fwa_result() {
    local resp status
    resp="$(cat)"
    status="$(fwa_xml status <<<"$resp")"
    echo "${status:-no answer}: $(fwa_xml msg <<<"$resp" | fwa_hide)"
    [[ "$status" == success ]]
}

fwa_xpath() {
    [[ "$1" == /config/* ]] || {
        pan_err "an xpath starts with /config/: $1"
        exit 2
    }
}

fwa_commit() {
    local desc="${1:-sfab fw-api}" resp status msg jid="" i
    for ((i = 1; i <= ${FWA_COMMIT_TRIES:-40}; i++)); do
        resp="$(fwa_api --data-urlencode type=commit \
            --data-urlencode "cmd=<commit><description>$(fwa_escape "$desc")</description></commit>" || true)"
        status="$(fwa_xml status <<<"$resp")"
        msg="$(fwa_xml msg <<<"$resp")"
        jid="$(fwa_xml job <<<"$resp")"
        if [[ "$status" == success && -n "$jid" ]]; then
            break
        fi
        if [[ "$status" == success && "${msg,,}" == *"no changes to commit"* ]]; then
            echo "commit: there are no changes to commit"
            return 0
        fi
        if [[ "${msg,,}" =~ $FWA_BUSY ]]; then
            echo "commit not queued yet: $msg"
            sleep "${FWA_COMMIT_PAUSE:-15}"
            jid=""
            continue
        fi
        echo "commit refused: ${msg:-no answer}"
        return 1
    done
    if [[ -z "$jid" ]]; then
        echo "commit still refused after ${FWA_COMMIT_TRIES:-40} tries"
        return 1
    fi
    echo "commit job $jid queued"
    local st res det
    for ((i = 1; i <= ${FWA_POLL_TRIES:-120}; i++)); do
        resp="$(fwa_api --data-urlencode type=op --data-urlencode "cmd=<show><jobs><id>$jid</id></jobs></show>" || true)"
        st="$(fwa_xml jobstatus <<<"$resp")"
        if [[ "$st" == FIN ]]; then
            res="$(fwa_xml jobresult <<<"$resp")"
            det="$(fwa_xml jobdetails <<<"$resp")"
            echo "commit job $jid: $res${det:+ ($det)}"
            [[ "$res" == OK ]]
            return
        fi
        sleep "${FWA_POLL_PAUSE:-5}"
    done
    echo "commit job $jid did not finish"
    return 1
}

# fwa_order XML: the running security and NAT rule order against the rendered file's.
fwa_order() {
    local file="$1" resp
    if [[ ! -r "$file" ]]; then
        pan_err "cannot read $file"
        return 2
    fi
    resp="$(fwa_api --data-urlencode type=config --data-urlencode action=show \
        --data-urlencode "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase" || true)"
    python3 -c '
import sys
import xml.etree.ElementTree as ET
want = ET.parse(sys.argv[1]).getroot().find("devices/entry/vsys/entry[@name=\x27vsys1\x27]/rulebase")
try:
    have = ET.fromstring(sys.stdin.buffer.read())
except ET.ParseError:
    print("order: the firewall gave no readable rulebase")
    sys.exit(1)
if have.get("status") != "success":
    print("order: the firewall answered " + str(have.get("status")))
    sys.exit(1)
have = have.find(".//rulebase") if have.find(".//rulebase") is not None else have
bad = 0
for kind in ("security", "nat"):
    w = [e.get("name") for e in (want.findall(kind + "/rules/entry") if want is not None else [])]
    h = [e.get("name") for e in have.findall(kind + "/rules/entry")]
    if w == h:
        print("order: %s %d rules as rendered" % (kind, len(w)))
    else:
        bad = 1
        print("order: %s differs; rendered: %s; running: %s" % (kind, " ".join(w) or "none", " ".join(h) or "none"))
sys.exit(bad)
' "$file" <<<"$resp"
}

fwa_main() {
    local lab=""
    if [[ "${1:-}" == --lab ]]; then
        [[ $# -ge 2 ]] || fwa_usage
        lab="$2"
        shift 2
    fi
    [[ $# -ge 1 ]] || fwa_usage
    local cmd="$1"
    shift
    case "$cmd" in
        get | show | del) [[ $# -eq 1 ]] || fwa_usage ;;
        set | edit | set-file) [[ $# -eq 2 ]] || fwa_usage ;;
        move) [[ $# -ge 1 && $# -le 3 ]] || fwa_usage ;;
        op) [[ $# -eq 1 ]] || fwa_usage ;;
        commit | order) [[ $# -le 1 ]] || fwa_usage ;;
        export-pcap) [[ $# -eq 2 ]] || fwa_usage ;;
        *) fwa_usage ;;
    esac
    case "$cmd" in
        get | show | del | set | edit | set-file | move) fwa_xpath "$1" ;;
    esac
    command -v curl >/dev/null 2>&1 || {
        pan_err "curl is not installed"
        exit 2
    }
    pan_init "$lab"
    FWA_URL="${SFAB_FW_API:-https://${PAN_HOST}/api/}"
    local rc=0
    fwa_keygen || rc=$?
    [[ "$rc" == 0 ]] || exit "$rc"
    case "$cmd" in
        get | show)
            fwa_api --data-urlencode type=config --data-urlencode "action=$cmd" --data-urlencode "xpath=$1" | fwa_hide
            echo
            ;;
        set | edit)
            fwa_api --data-urlencode type=config --data-urlencode "action=$cmd" --data-urlencode "xpath=$1" \
                --data-urlencode "element=$2" | fwa_result
            ;;
        set-file)
            [[ -r "$2" ]] || {
                pan_err "cannot read $2"
                exit 2
            }
            fwa_api --data-urlencode type=config --data-urlencode action=set --data-urlencode "xpath=$1" \
                --data-urlencode "element@$2" | fwa_result
            ;;
        del)
            fwa_api --data-urlencode type=config --data-urlencode action=delete --data-urlencode "xpath=$1" | fwa_result
            ;;
        move)
            local where="${2:-before}" dst="${3:-}"
            if [[ "$where" == before || "$where" == after ]]; then dst="${dst:-deny-all-log}"; fi
            if [[ -n "$dst" ]]; then
                fwa_api --data-urlencode type=config --data-urlencode action=move --data-urlencode "xpath=$1" \
                    --data-urlencode "where=$where" --data-urlencode "dst=$dst" | fwa_result
            else
                fwa_api --data-urlencode type=config --data-urlencode action=move --data-urlencode "xpath=$1" \
                    --data-urlencode "where=$where" | fwa_result
            fi
            ;;
        op)
            fwa_api --data-urlencode type=op --data-urlencode "cmd=$1" | fwa_hide
            echo
            ;;
        commit) fwa_commit "${1:-}" ;;
        order) fwa_order "${1:-$PAN_LABDIR/bootstrap/fw/startup-config.xml}" ;;
        export-pcap) fwa_export_pcap "$1" "$2" ;;
    esac
}

fwa_main "$@"
