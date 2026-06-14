#!/bin/bash
#
# Dependency installer for the Volatility 3 version of malscan.
#
# Volatility 3 ships its own disassembler (capstone), so distorm3 is no longer
# needed. The only external dependency is ClamAV (engine + daemon), which the
# plugin talks to over its Unix socket.

if [ "$EUID" -ne 0 ]; then
    echo "Root required"
    exit 1
fi

# Volatility 3 (skip if you already have it installed system-wide)
echo -e "\n[*] Installing Volatility 3...\n"
pip3 install volatility3

# System dependencies
echo -e "\n[*] Updating list of available packages...\n"
apt-get update

echo -e "\n[*] Installing ClamAV (engine + daemon)...\n"
APT_OUTPUT="$(apt-get install -y clamav clamav-daemon)"
echo "$APT_OUTPUT"

# clamav-daemon needs a running daemon and a Unix socket. The default socket
# path expected by the plugin is /run/clamav/clamd.ctl (configurable with
# --clamd-socket). You may need to start the service and update the signatures:
echo -e "\n[*] Ensure the daemon is running and signatures are up to date, e.g.:"
echo    "      systemctl enable --now clamav-daemon"
echo    "      freshclam"
echo -e "\nYou may need to reboot your system to start the ClamAV daemon.\n"
