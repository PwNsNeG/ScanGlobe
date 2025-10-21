#!/usr/bin/env python3
import argparse, subprocess, pathlib, os, sys

def run(cmd):
    print("[+] " + " ".join(cmd))
    subprocess.check_call(cmd)

def scan_one(iso, ports, rate, iface, extra):
    path = pathlib.Path(f"data/countries/{iso}.txt")
    if not path.exists():
        sys.exit(f"missing {path}")
    out = pathlib.Path(f"out/{iso}-raw.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["masscan", f"-p{ports}", "-iL", str(path), "--rate", str(rate), "--open", "--banners",
           "--output-format","json","--output-filename", str(out)]
    if extra: cmd += extra
    run(cmd)

def scan_bulk(ports, rate, iface, extra):
    d = pathlib.Path("data/countries")
    if not d.exists(): sys.exit("missing data/countries/")
    for f in sorted(d.glob("*.txt")):
        iso = f.stem.upper()
        scan_one(iso, ports, rate, iface, extra)

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("scan", help="scan one ISO")
    s1.add_argument("iso")
    s1.add_argument("--ports", default=os.getenv("PORTS","80,443"))
    s1.add_argument("--rate", type=int, default=int(os.getenv("RATE","15000")))
    s1.add_argument("--iface", default=os.getenv("IFACE","eth0"))
    s1.add_argument("--extra", nargs=argparse.REMAINDER, help="extra masscan flags")

    s2 = sub.add_parser("scan-bulk", help="scan all countries")
    s2.add_argument("--ports", default=os.getenv("PORTS","80,443"))
    s2.add_argument("--rate", type=int, default=int(os.getenv("RATE","15000")))
    s2.add_argument("--iface", default=os.getenv("IFACE","eth0"))
    s2.add_argument("--extra", nargs=argparse.REMAINDER)

    args = p.parse_args()
    if args.cmd == "scan":
        scan_one(args.iso, args.ports, args.rate, args.iface, args.extra)
    else:
        scan_bulk(args.ports, args.rate, args.iface, args.extra)

if __name__ == "__main__":
    main()

