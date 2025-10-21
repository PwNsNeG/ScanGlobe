#!/usr/bin/env bash
set -euo pipefail
ISO="${1:?ISO country code (e.g., IT)}"
RAW="${2:?Path to masscan raw JSON file}"

RUN_TS="$(date -u +'%Y-%m-%dT%H-%M-%SZ')"
OUTDIR="out/$ISO"; mkdir -p "$OUTDIR"
OUTFILE="$OUTDIR/${ISO}-${RUN_TS}.jsonl"

jq -c --arg st "$RUN_TS" '
  (if type=="array" then .[] else . end)
  | select(.ip and .ports and (.ports|length>0))
  | . as $r
  | .ports[]
  | {
      ip: $r.ip,
      port: .port,
      proto: (.proto // "tcp"),
      status: (.status // "open"),
      reason: (.reason // null),
      ttl: (.ttl // null),
      banner: (.service.banner // null),
      event_ts_unix: ($r.timestamp|tonumber),
      scan_time_iso: $st
    }
' "$RAW" > "$OUTFILE"

ln -sfn "$(basename "$OUTFILE")" "$OUTDIR/latest"

COUNT=$(wc -l < "$OUTFILE")
mkdir -p out
printf '{"iso":"%s","scan_time_iso":"%s","file":"%s","lines":%s}\n' \
  "$ISO" "$RUN_TS" "$OUTFILE" "$COUNT" >> out/manifest.jsonl

echo "[*] Wrote $OUTFILE ($COUNT lines) and updated $OUTDIR/latest"

