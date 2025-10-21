#!/usr/bin/env python3
"""
Enrich Masscan results (raw JSON or JSONL) with WHOIS org and optional ASN/BGP info.

Usage examples:
  # Raw Masscan JSON (array/object)
  python3 enrich_whois.py --in out/IT-raw.json --out out/IT-enriched.jsonl

  # Already-normalized JSONL (e.g., {ip, port, ts, banner})
  python3 enrich_whois.py --in out/IT.jsonl --out out/IT-enriched.jsonl

  # Add ASN/BGP (Team Cymru) and force AFRINIC first (good for 41.x space), throttle lookups
  python3 enrich_whois.py --in out/IT.jsonl --out out/IT-enriched.jsonl --asn --force-rir afrinic --sleep-ms 50

Requirements:
  sudo apt-get -y install whois
"""

import argparse
import json
import pathlib
import re
import sqlite3
import subprocess
import time
from typing import Optional, Dict

# ---------- Config ----------

RIRS = {
    "arin":    "whois.arin.net",
    "ripe":    "whois.ripe.net",
    "apnic":   "whois.apnic.net",
    "afrinic": "whois.afrinic.net",
    "lacnic":  "whois.lacnic.net",
}

# Keys most likely to carry an organization/owner name across RIRs.
ORG_KEYS_ORDER = ("OrgName", "org-name", "orgname", "organisation", "owner", "custname", "responsible")

# ---------- Shell helper ----------

def sh(args, timeout: int = 8) -> str:
    """Run a command and return stdout as text, or '' on failure."""
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""

# ---------- WHOIS helpers ----------

def parse_kv_whois(txt: str) -> Dict[str, str]:
    """Parse 'key: value' lines into a dict (first occurrence wins)."""
    kv = {}
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k and (k not in kv) and v:
            kv[k] = v
    return kv

def parse_org_from_text(txt: str) -> Optional[str]:
    """Extract an organization-like field (with sensible fallback to a clean 'descr')."""
    kv = parse_kv_whois(txt)

    # 1) Explicit org-like keys
    for k in ORG_KEYS_ORDER:
        if k in kv and kv[k]:
            return kv[k]

    # 2) Fallback to a reasonable 'descr' (skip boilerplate)
    for k, v in kv.items():
        if k.lower() == "descr" and v:
            low = v.lower()
            if not re.search(r"(abuse|noc|hostmaster|po box|disclaimer)", low):
                return v

    return None

def detect_rir_server(ip: str) -> Optional[str]:
    """Ask default whois and try to detect referral or RIR hints."""
    txt = sh(["whois", ip])
    # Look for explicit referral (refer: / whois:)
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() in ("refer", "whois"):
            host = v.strip().lower()
            if host:
                return host
    # Fallback: keyword hints
    low = txt.lower()
    if "afrinic" in low: return RIRS["afrinic"]
    if "ripe"    in low: return RIRS["ripe"]
    if "apnic"   in low: return RIRS["apnic"]
    if "lacnic"  in low: return RIRS["lacnic"]
    if "arin"    in low: return RIRS["arin"]
    return None

def whois_org(ip: str, force_rir: Optional[str] = None) -> Optional[str]:
    """
    Resolve org for an IP.
    - Try default whois.
    - Then try forced RIR (if provided) with -B (unfiltered where supported, e.g., AFRINIC).
    - Then referred/guessed RIR.
    - Finally, try remaining RIRs.
    """
    # 0) Default whois first (cheap win if it already resolves)
    txt0 = sh(["whois", ip])
    org0 = parse_org_from_text(txt0)
    if org0:
        return org0

    # Build server list to try in order
    servers = []
    if force_rir:
        servers.append(RIRS[force_rir])

    referred = detect_rir_server(ip)
    if referred and referred not in servers:
        servers.append(referred)

    # Fill remaining with a stable order
    for host in (RIRS["afrinic"], RIRS["ripe"], RIRS["apnic"], RIRS["lacnic"], RIRS["arin"]):
        if host not in servers:
            servers.append(host)

    # Try each server; use -B (e.g., AFRINIC) to get unfiltered results when supported
    for host in servers:
        txt = sh(["whois", "-B", "-h", host, ip])
        org = parse_org_from_text(txt)
        if org:
            return org

    return None

# ---------- Team Cymru ASN enrichment ----------

def cymru_asn(ip: str) -> Optional[Dict[str, Optional[str]]]:
    """
    Query Team Cymru whois for ASN info.
    Output columns: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    """
    out = sh(["whois", "-h", "whois.cymru.com", " -v " + ip], timeout=8)
    if not out:
        return None
    lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith(("AS", "#"))]
    if not lines:
        return None
    parts = [p.strip() for p in lines[0].split("|")]
    if len(parts) < 7:
        return None
    asn, _ip, prefix, cc, _reg, _alloc, asname = parts[:7]

    def nn(x: str) -> Optional[str]:
        return None if x in ("", "NA", "N/A", "-") else x

    return {
        "asn": nn(asn),
        "bgp_prefix": nn(prefix),
        "cc": nn(cc),
        "as_name": nn(asname),
    }

# ---------- Cache (SQLite) ----------

def open_cache(path: pathlib.Path):
    db = sqlite3.connect(path)
    db.execute("""
        CREATE TABLE IF NOT EXISTS whois_cache (
            ip TEXT PRIMARY KEY,
            org TEXT,
            asn TEXT,
            bgp_prefix TEXT,
            cc TEXT,
            as_name TEXT,
            ts INTEGER
        );
    """)
    return db

def get_cached(db, ip: str) -> Optional[Dict[str, Optional[str]]]:
    row = db.execute(
        "SELECT org, asn, bgp_prefix, cc, as_name FROM whois_cache WHERE ip=?",
        (ip,)
    ).fetchone()
    if not row:
        return None
    org, asn, bgp, cc, asname = row
    return {
        "whois_org": org,
        "asn": asn,
        "bgp_prefix": bgp,
        "cc": cc,
        "as_name": asname,
    }

def set_cache(db, ip: str, data: Dict[str, Optional[str]]) -> None:
    db.execute(
        "INSERT OR REPLACE INTO whois_cache(ip, org, asn, bgp_prefix, cc, as_name, ts) VALUES(?,?,?,?,?,?,?)",
        (ip, data.get("whois_org"), data.get("asn"), data.get("bgp_prefix"),
         data.get("cc"), data.get("as_name"), int(time.time()))
    )
    db.commit()

# ---------- Input iteration (Masscan raw JSON or JSONL) ----------

def iter_events(fp):
    """
    Yield dicts with at least 'ip' (and pass through existing fields).
    Accepts:
      - Masscan raw JSON (array/object)
      - JSONL (one JSON object per line)
    """
    head = fp.read(2)
    if not head:
        return
    is_json_array = head.strip().startswith("[")
    fp.seek(0)

    if is_json_array:
        data = json.load(fp)
        objs = data if isinstance(data, list) else [data]
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            # Masscan raw format: {"ip": "...", "timestamp": ..., "ports":[{...}]}
            if "ip" in obj and "ports" in obj:
                p0 = (obj.get("ports") or [{}])[0]
                yield {
                    "ip": obj.get("ip"),
                    "port": p0.get("port"),
                    "proto": p0.get("proto"),
                    "ts": obj.get("timestamp"),
                    "banner": (p0.get("service") or {}).get("banner"),
                }
    else:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("ip"):
                yield obj

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(description="Enrich Masscan JSON/JSONL with WHOIS org and optional ASN/BGP info.")
    ap.add_argument("--in", dest="inp", required=True, help="Input file: Masscan raw JSON (array/object) or JSONL")
    ap.add_argument("--out", dest="outp", required=True, help="Output JSONL path")
    ap.add_argument("--cache", default="out/whois_cache.sqlite",
                    help="SQLite cache path (default: out/whois_cache.sqlite)")
    ap.add_argument("--asn", action="store_true", help="Also query Team Cymru for ASN/BGP prefix/AS name")
    ap.add_argument("--force-rir", choices=list(RIRS.keys()),
                    help="Query this RIR server first (e.g., afrinic, ripe). Uses -B where supported.")
    ap.add_argument("--sleep-ms", type=int, default=0,
                    help="Sleep between NEW IP lookups (milliseconds)")
    args = ap.parse_args()

    inp = pathlib.Path(args.inp)
    outp = pathlib.Path(args.outp)
    outp.parent.mkdir(parents=True, exist_ok=True)

    db = open_cache(pathlib.Path(args.cache))

    with inp.open("r") as r, outp.open("w") as w:
        for ev in iter_events(r):
            ip = ev.get("ip")
            if not ip:
                continue

            info = get_cached(db, ip)
            if not info:
                # fresh lookups
                org = whois_org(ip, force_rir=args.force_rir)
                info = {"whois_org": org}
                if args.asn:
                    asn_info = cymru_asn(ip)
                    if asn_info:
                        info.update(asn_info)
                set_cache(db, ip, info)
                if args.sleep_ms:
                    time.sleep(args.sleep_ms / 1000.0)

            enriched = dict(ev)
            enriched["whois_org"] = info.get("whois_org")
            if args.asn:
                enriched["asn"] = info.get("asn")
                enriched["bgp_prefix"] = info.get("bgp_prefix")
                enriched["cc"] = info.get("cc")
                enriched["as_name"] = info.get("as_name")

            w.write(json.dumps(enriched) + "\n")

if __name__ == "__main__":
    main()

