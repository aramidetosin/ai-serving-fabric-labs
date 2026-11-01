# shellcheck shell=bash
# common/break/lib-k8sbreak.sh: Part III's break actions (chapters 8, 9 and 11), sourced by
# common/break/breakheal.sh after lib.sh, with its helpers (jf, jg, ok, bad, RS, MODE).
#
#   k8s_patch_action JSON TAG      one cluster object changed in place with kubectl patch --type merge
#                                  (an audience's announcement policy's interfaces, a model route's
#                                  rules), the object read whole after it; the heal's patch is the
#                                  rendered fields
#   k8s_read_action JSON TAG       the objects behind a Gateway read whole (kubectl get -o yaml)
#   dnsmasq_pin_action JSON TAG    the corporate resolver's dnsmasq.conf as the break renders it,
#                                  installed in a copy of its render and the server restarted on it
#                                  (sfab-dns reload); restore of the node puts the render back
#   lookup_probe_action JSON       a client's lookups of one name by each stub it has: dig for A and
#                                  for AAAA (the answer's status and records), python3's getaddrinfo
#                                  (musl) and curl (its own resolver library), each timed, with its
#                                  output and exit status, into probes/<id>-<mode>/
#   lookup_check JSON              what a lookup answered, against the check (breakheal.py lookup)
#
# Nothing here prints a credential; the patches name objects and fields only.

# k8s_json JSON KEY: one field of an action as JSON (jf prints a mapping as Python would)
k8s_json() { py -c 'import json, sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]], sort_keys=True))' "$1" "$2"; }

k8s_patch_action() {
  local js="$1" tag="$2" res name ns out patch
  res="$(jf "$js" resource)" name="$(jf "$js" name)" ns="$(jg "$js" namespace)"
  patch="$(k8s_json "$js" patch)"
  out="$RS/record/$tag-patch-$name.txt"
  printf '%s\n' "$patch" >"$RS/record/$tag-patch-$name.json"
  if K ${ns:+-n "$ns"} patch "$res" "$name" --type merge -p "$patch" >"$out" 2>&1; then
    ok "$(jf "$js" summary)"
    printf 'patched %s %s\n' "$res" "$name" >>"$RS/taken.txt"
  else
    bad "$(jf "$js" summary)" "$(tail -n 1 "$out")"
    return 1
  fi
  K ${ns:+-n "$ns"} get "$res" "$name" -o yaml >"$RS/record/$tag-$name.yaml" 2>&1 || true
}

k8s_read_action() {
  local js="$1" tag="$2" rows id res ns name
  rows="$(py -c 'import json, sys
for o in json.loads(sys.argv[1])["objects"]:
    print("\t".join([o["id"], o["resource"], o["namespace"] or "-", o["name"]]))' "$js")"
  while IFS=$'\t' read -r id res ns name; do
    [ -n "$id" ] || continue
    [ "$ns" != - ] || ns=""
    K ${ns:+-n "$ns"} get "$res" "$name" -o yaml >"$RS/record/$tag-$(printf '%s' "$id" | tr -cs 'A-Za-z0-9' '-' | sed 's/-$//').yaml" 2>&1 || true
  done <<<"$rows"
  ok "$tag: $(py -c 'import json, sys; print(", ".join(o["id"] for o in json.loads(sys.argv[1])["objects"]))' "$js") read whole (record/$tag-*.yaml)"
}

dnsmasq_pin_action() {
  local js="$1" tag="$2" node dir f c rec
  node="$(jf "$js" node)" dir="$(jf "$js" dir)" f="$(jf "$js" file)"
  c="$(ctr "$node")"
  rec="$RS/record/$tag-$node-$f.txt"
  py -c 'import json, sys; sys.stdout.write(json.loads(sys.argv[1])["content"])' "$js" >"$rec"
  X "$node" sh -c "rm -rf $dir && mkdir -p $dir && cp -R /sfab/bootstrap/. $dir/" >"$RS/record/$tag-$node-copy.txt" 2>&1 || true
  _evid "$node" container "+ cat >$dir/$f (record/$(basename "$rec"))"
  dk exec -i "$c" sh -c "cat >$dir/$f" <"$rec" || { bad "$node: dnsmasq.conf written" "docker exec failed"; return 1; }
  if X "$node" sfab-dns reload "$dir" >"$RS/record/$tag-$node-reload.txt" 2>&1; then
    ok "$node: the platform's zone no longer forwarded; $(jf "$js" names | paste -sd ' ' -) pinned to $(jf "$js" address) with address=; dnsmasq restarted on the copy ($(tail -n 1 "$RS/record/$tag-$node-reload.txt"))"
  else
    bad "$node: dnsmasq restarted with the pins" "$(tail -n 2 "$RS/record/$tag-$node-reload.txt" | paste -sd ';' -)"
    return 1
  fi
}

lookup_probe_action() {
  local js="$1" pid node name url to d t
  pid="$(jf "$js" id)" node="$(jf "$js" node)" name="$(jf "$js" name)" url="$(jf "$js" url)" to="$(jf "$js" timeout_s)"
  d="$RS/probes/$pid-$MODE"
  mkdir -p "$d"
  X "$node" cat /etc/resolv.conf >"$d/resolv.conf" 2>&1 || true
  for t in $(jf "$js" tools); do
    case "$t" in
      dig-a) X "$node" sh -c "s=\$(date +%s.%N); dig +tries=1 +time=5 $name A; echo \"exit \$? start \$s end \$(date +%s.%N)\"" >"$d/$t.txt" 2>&1 || true ;;
      dig-aaaa) X "$node" sh -c "s=\$(date +%s.%N); dig +tries=1 +time=5 $name AAAA; echo \"exit \$? start \$s end \$(date +%s.%N)\"" >"$d/$t.txt" 2>&1 || true ;;
      getaddrinfo)
        dk exec -i "$(ctr "$node")" sh -c 'cat >/tmp/sfab-gai.py' <<'PY' || true
import socket
import sys

try:
    print(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 443)}))
except socket.gaierror as e:
    print("gaierror", e.errno, e)
    sys.exit(2)
PY
        X "$node" sh -c "s=\$(date +%s.%N); timeout $to python3 /tmp/sfab-gai.py $name; echo \"exit \$? start \$s end \$(date +%s.%N)\"" >"$d/$t.txt" 2>&1 || true ;;
      curl) X "$node" sh -c "s=\$(date +%s.%N); timeout $to curl -sS -o /dev/null -w 'http %{http_code} remote %{remote_ip}\n' --max-time $to '$url'; echo \"exit \$? start \$s end \$(date +%s.%N)\"" >"$d/$t.txt" 2>&1 || true ;;
    esac
  done
  ok "$pid, $MODE: $node looked up $name with $(jf "$js" tools | paste -sd ' ' -) ($(py "$BH" lookup --dir "$d" --summary))"
  echo lookup >"$RS/probes/$pid-$MODE.kind"
}

lookup_check() {
  local js="$1" out
  if out="$(py "$BH" lookup --dir "$RS/probes/$(jf "$js" probe)-$MODE" --check "$js")"; then
    ok "$(jf "$js" probe): $out"
  else
    bad "$(jf "$js" probe): $(py -c 'import json, sys; c = json.loads(sys.argv[1]); print(c.get("tool") or c["type"], "as the check wants")' "$js")" "$out"
  fi
}
