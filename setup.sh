#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Root required"
    exit
fi

# Python dependencies
echo -e "\n[*] Installing Python2 dependencies...\n"
sudo pip2 install distorm3

# System dependencies
echo -e "[*] Updating list of available packages...\n"
sudo apt-get update

echo -e "\n[*] Installing system dependencies...\n"
APT_OUTPUT="$(sudo apt-get install python-dev clamav clamav-daemon)"
echo "$APT_OUTPUT"

# clamav-daemon needs a system reboot to install unix pipe and start daemon
if [[ $APT_OUTPUT != *"0 upgraded"* ]] || [[ $APT_OUTPUT != *"0 newly installed"* ]]; then
    echo -e "\nDone. You may need to reboot your system.\n"
fi
