#!/usr/bin/env bash
# ScanGlobe pipeline: scan -> normalize -> enrich -> stamp (per-country)
# Usage:
#   scripts/pipeline_country.sh IT 22,80,443
#   PORTS=22,80,443 RATE=12000 scripts/pipeline_country.sh FR
# Env knobs:
#   RATE=15000 IFACE=eth0 SLEEP_MS=50 WITH_ASN=1 FORCE_RIR=afrinic

set -euo pipefail

# ---- args & defaults ----
ISO="${1:-}"; [[ -n "$ISO" ]] || { echo "usage: $0 <ISO> [ports]"; exit 1; }
PORTS="${2:-${PORTS:-80,443}}"
RATE="${RATE:-15000}"
IFACE="${IFACE:-eth0}"
SLEEP_MS="${SLEEP_MS:-50}"          # whois throttle (ms)
WITH_ASN="${WITH_ASN:-1}"           # 1=yes (add ASN/BGP), 0=no
FORCE_RIR="${FORCE_RIR:-}"          # afrinic|ripe|apnic|lacnic|arin (blank = auto)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RAW="${ROOT}/out/${ISO}-raw.json"
NORM="${ROOT}/out/${ISO}-norm.jsonl"
ENRICHED="${ROOT}/out/${ISO}-enriched.jsonl"
OUT_DIR="${ROOT}/out/${ISO}"

# ---- deps ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need python3
need jq

[[ -f "${ROOT}/tools/cli.py" ]] || { echo "tools/cli.py not found"; exit 1; }
[[ -f "${ROOT}/tools/enrich_whois.py" ]] || { echo "tools/enrich_whois.py not found"; exit 1; }
[[ -f "${ROOT}/data/countries/${ISO}.txt" ]] || { echo "missing data/countries/${ISO}.txt"; exit 1; }

mkdir -p "${ROOT}/out" "${OUT_DIR}"

echo "[*] scan: ISO=${ISO} PORTS=${PORTS} RATE=${RATE} IFACE=${IFACE}"
# Run your existing CLI. We pass raw output path explicitly using --extra (forwarded to masscan).
python3 "${ROOT}/tools/cli.py" scan "${ISO}" \
  --ports "${PORTS}" --rate "${RATE}" --iface "${IFACE}" \
  --extra --output-format json --output-filename "${RAW}"

[[ -s "${RAW}" ]] || { echo "[!] raw scan output empty: ${RAW}"; exit 1; }

echo "[*] normalize: ${RAW} -> ${NORM}"
# Normalize Masscan raw -> minimal canonical JSONL
jq -c '
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
      event_ts_unix: ($r.timestamp|tonumber)
    }
' "${RAW}" > "${NORM}"

[[ -s "${NORM}" ]] || { echo "[!] normalization produced empty output: ${NORM}"; exit 1; }

echo "[*] enrich: ${NORM} -> ${ENRICHED}"
EN_ARGS=( --in "${NORM}" --out "${ENRICHED}" --sleep-ms "${SLEEP_MS}" )
[[ "${WITH_ASN}" == "1" ]] && EN_ARGS+=( --asn )
[[ -n "${FORCE_RIR}" ]] && EN_ARGS+=( --force-rir "${FORCE_RIR}" )

set +e
python3 "${ROOT}/tools/enrich_whois.py" "${EN_ARGS[@]}"
rc=$?; set -e
if [[ $rc -ne 0 || ! -s "${ENRICHED}" ]]; then
  echo "[!] enrichment failed or empty; falling back to normalized (no WHOIS)."
  cp -f "${NORM}" "${ENRICHED}"
fi

# ---- stamp per-country file + latest symlink + manifest ----
RUN_TS="$(date -u +'%Y-%m-%dT%H-%M-%SZ')"
OUTFILE="${OUT_DIR}/${ISO}-${RUN_TS}.jsonl"
echo "[*] stamp: ${ENRICHED} -> ${OUTFILE}"

jq -c --arg st "${RUN_TS}" --arg src "$(basename "${RAW}")" --arg iso "${ISO}" '
  . as $e
  | {
      ip: $e.ip,
      port: ($e.port|tonumber),
      proto: ($e.proto // "tcp"),
      status: ($e.status // "open"),
      reason: ($e.reason // null),
      ttl: ($e.ttl // null),
      banner: ($e.banner // null),
      event_ts_unix: ($e.event_ts_unix // null),
      scan_time_iso: $st,
      source_file: $src,
      country: $iso,
      whois_org: ($e.whois_org // null),
      asn: ($e.asn // null),
      bgp_prefix: ($e.bgp_prefix // null),
      cc: ($e.cc // null),
      as_name: ($e.as_name // null)
    }
' "${ENRICHED}" > "${OUTFILE}"

ln -sfn "$(basename "${OUTFILE}")" "${OUT_DIR}/latest"
COUNT=$(wc -l < "${OUTFILE}")
printf '{"iso":"%s","scan_time_iso":"%s","file":"%s","lines":%s}\n' \
  "${ISO}" "${RUN_TS}" "${OUTFILE}" "${COUNT}" >> "${ROOT}/out/manifest.jsonl"

echo "[✓] done: ${OUTFILE} (${COUNT} lines)"
echo "    latest -> $(readlink -f "${OUT_DIR}/latest")"

if [ -L "${OUT_DIR}/latest" ]; then
  LATEST="$(readlink -f "${OUT_DIR}/latest")"
else
  # fallback: pick most recent timestamped file
  LATEST="$(ls -1 "${OUT_DIR}/${ISO}-"*.jsonl 2>/dev/null | sort | tail -1)"
fi

if [ -n "${LATEST:-}" ] && [ -f "$LATEST" ]; then
  # GNU sort in-place; if uncertain, use the temp-file fallback below
  sort -u -o "$LATEST" "$LATEST"
  # Temp-file fallback:
  # tmp="${LATEST}.tmp"; sort -u "$LATEST" > "$tmp" && mv "$tmp" "$LATEST"
else
  echo "[!] Could not resolve latest file to dedupe (symlink or file missing)" >&2
fi

# totals
wc -l "$LATEST"
jq -r '.ip' "$LATEST" | sort -u | wc -l
jq -r '.ip+":"+(.port|tostring)' "$LATEST" | sort -u | wc -l

# top ports / ASNs / orgs
jq -r '.port' "$LATEST" | sort | uniq -c | sort -nr | head
jq -r 'select(.asn) | .asn' "$LATEST" | sort | uniq -c | sort -nr | head
jq -r 'select(.whois_org) | .whois_org' "$LATEST" | sed 's/\s\+/ /g' | sort | uniq -c | sort -nr | head
