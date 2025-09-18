# ScanGlobe
Country-scoped internet scanning pipeline that discovers open ports by country, verifies findings, and exports clean IP lists.
    -Fast discovery with masscan, per-country inputs
    -nmap verification (banner/TLS) to cut false positives
    -Optional WHOIS org enrichment
    -JSONL per country/port + easy export of IP lists
    -Resume-ready, reproducible, minimal dependencies
