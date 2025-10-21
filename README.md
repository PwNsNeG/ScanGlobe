# ScanGlobe
Country-scoped internet scanning pipeline that discovers open ports by country, verifies findings, and exports clean IP lists.
    -Fast discovery with masscan, per-country inputs
    -nmap verification (banner/TLS) to cut false positives
    -Optional WHOIS org enrichment
    -JSONL per country/port + easy export of IP lists
    -Resume-ready, reproducible, minimal dependencies


sudo ./setup_masscan.sh 

python3 tools/cli.py scan IT --ports 80,443 --rate 15000
python3 tools/cli.py scan-bulk --ports 22,80,443 --rate 12000 --extra --exclude-file do_not_scan.txt
