#!/usr/bin/env bash
# build-if-stale.sh: build an image only when it is missing, or when a watched file is newer than
# the image (FRAMEWORK.md section 5: an image rebuilds when its build context is newer).
#
#   build-if-stale.sh <image ref> <context dir> [--watch <path>]... [--force] [-- <docker build args>]
#
# Without --watch the whole context directory is watched. FORCE=1 in the environment, or
# --force, builds regardless.
set -euo pipefail

die() { printf '[build] FATAL: %s\n' "$*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: build-if-stale.sh <image ref> <context dir> [--watch <path>]... [--force] [-- <docker build args>]"
ref=$1
ctx=$2
shift 2
watch=()
force=${FORCE:-0}
while [ $# -gt 0 ]; do
  case $1 in
    --watch) [ $# -ge 2 ] || die "--watch needs a path"; watch+=("$2"); shift 2 ;;
    --force) force=1; shift ;;
    --) shift; break ;;
    *) die "unknown option $1" ;;
  esac
done
[ -d "$ctx" ] || die "no build context $ctx"
if [ "${#watch[@]}" -eq 0 ]; then watch=("$ctx"); fi

reason=""
created=$(docker image inspect -f '{{.Created}}' "$ref" 2>/dev/null || true)
if [ "$force" = 1 ]; then
  reason="forced"
elif [ -z "$created" ]; then
  reason="not built yet"
else
  built=$(date -d "$created" +%s)
  for p in "${watch[@]}"; do
    [ -e "$p" ] || die "watched path $p does not exist"
  done
  newest=$(find "${watch[@]}" -type f -printf '%T@ %p\n' | sort -n | tail -n 1)
  if [ -n "$newest" ] && [ "${newest%%.*}" -gt "$built" ]; then
    reason="${newest#* } is newer than the image"
  fi
fi

if [ -z "$reason" ]; then
  printf '[build] %s is current\n' "$ref"
  exit 0
fi
printf '[build] %s: %s\n' "$ref" "$reason"
docker build -t "$ref" "$@" "$ctx"
