#!/bin/bash
# SSH Brute Force Detector - Local Setup & Test Script
# Works on Kali Linux (Debian-based)

sudo apt-get update
sudo apt install -y tshark iptables python3 python3-pip hydra openssh-client

pip3 install -r requirements.txt || true

sudo adduser testuser
sudo passwd ssh_test

sudo usermod -s /bin/bash ssh_test

# Ensure SSH server is running
echo "[*] Checking SSH service..."
if ! sudo systemctl is-active --quiet ssh; then
    echo "[*] Enabling and starting SSH service..."
    sudo systemctl enable ssh
    sudo systemctl start ssh
fi

sudo iptables -F
sudo ufw allow 22/tcp

# Verify port 22 is open
echo "[*] Verifying SSH is listening on port 22..."
if ! sudo netstat -tulpn | grep -q ":22"; then
    echo "[!] SSH port 22 is not open. Trying to fix..."
    sudo systemctl restart ssh
    sleep 2
    if ! sudo netstat -tulpn | grep -q ":22"; then
        echo "[ERROR] SSH server did not start properly. Exiting."
        exit 1
    fi
fi
echo "[+] SSH server running on port 22"


