#!/usr/bin/env bash
set -euo pipefail
OLD="${1:?old file (e.g., out/IT/IT-2025-10-20T10-00-00Z.jsonl)}"
NEW="${2:?new file (e.g., out/IT/IT-2025-10-21T12-05-01Z.jsonl)}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

jq -r '.ip+":"+(.port|tostring)' "$OLD" | sort -u > "$tmpdir/old.txt"
jq -r '.ip+":"+(.port|tostring)' "$NEW" | sort -u > "$tmpdir/new.txt"

echo "== Newly open =="
comm -13 "$tmpdir/old.txt" "$tmpdir/new.txt" || true

echo
echo "== Now closed =="
comm -23 "$tmpdir/old.txt" "$tmpdir/new.txt" || true

echo
echo "== Banner changed =="
join -t $'\t' -j 1 \
  <(jq -r '.ip+":"+(.port|tostring)+"\t"+(.banner//"")' "$OLD" | sort) \
  <(jq -r '.ip+":"+(.port|tostring)+"\t"+(.banner//"")' "$NEW" | sort) \
| awk -F'\t' '$2!=$3 {print $1"\tOLD=" $2 "\tNEW=" $3}'

