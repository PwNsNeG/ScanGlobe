#!/usr/bin/env bash
set -euo pipefail

# ===== Config =====
TEST_PORTS="80"
TEST_CIDR="10.0.0.0/24"     # test network 
TEST_RATE="1000"            # packets per second
MASSCAN_REPO="https://github.com/robertdavidgraham/masscan"
PREFIX="/usr/local"

# ===== Detect Ubuntu/Debian and install build deps =====
echo "[*] Updating package lists and installing build dependencies..."
sudo apt-get update
sudo apt-get --assume-yes install git make gcc build-essential libpcap-dev ca-certificates

# ===== Clone & build masscan =====
WORKDIR="$(mktemp -d)"
echo "[*] Cloning masscan into $WORKDIR"
git clone --depth=1 "$MASSCAN_REPO" "$WORKDIR/masscan"
cd "$WORKDIR/masscan"

echo "[*] Building masscan..."
make -j"$(nproc)" 

echo "[*] Installing masscan to $PREFIX/bin (may prompt for sudo)..."
sudo make install PREFIX="$PREFIX"

# ===== Allow non-root usage (raw sockets) =====
# This lets you run 'masscan' without sudo. Remove with: sudo setcap -r $(command -v masscan)
if command -v setcap >/dev/null 2>&1; then
  echo "[*] Granting CAP_NET_RAW and CAP_NET_ADMIN to masscan binary for non-root use..."
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)" || true
else
  echo "[!] 'setcap' not found; install 'libcap2-bin' if you want non-root execution: sudo apt-get install libcap2-bin"
fi

# ===== Show version =====
echo "[*] Installed masscan version:"
masscan --version || true

# ===== Quick interface hint =====
IFACE="$(ip -o -4 route show to default | awk '{print $5}' | head -n1 || true)"
echo "[*] Detected default interface: ${IFACE:-unknown}"
echo "    If you have multiple NICs, you can specify: --adapter ${IFACE}"

# ===== Run a SAFE quick test scan =====
echo
echo "[*] Running test scan:"
echo "    masscan -p${TEST_PORTS} ${TEST_CIDR} --rate=${TEST_RATE}"
echo "    (Tip: add --adapter ${IFACE} if needed)"
echo
