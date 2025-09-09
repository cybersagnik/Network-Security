#!/bin/bash
# restore.sh - Restore system firewall state after running SSH Brute Force Detector
# Usage: sudo ./restore.sh

echo "[*] Restoring system firewall state..."

# Require root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (use sudo)."
    exit 1
fi

# Flush all custom iptables rules
echo "[*] Flushing iptables rules..."
iptables -F
iptables -X
iptables -Z

# Set default policies to ACCEPT
echo "[*] Resetting default policies..."
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Flush NAT table rules
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z

# Flush mangle table rules
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z

# Restore IPv6 as well (if enabled)
if command -v ip6tables >/dev/null 2>&1; then
    echo "[*] Flushing IPv6 iptables rules..."
    ip6tables -F
    ip6tables -X
    ip6tables -Z
    ip6tables -P INPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
    ip6tables -P OUTPUT ACCEPT
fi

echo "[+] Firewall rules have been reset to default (ACCEPT all)."
echo "[+] System state restored successfully."

#Important: This resets all firewall rules — useful for testing environments, but in production you may want to save & restore only the rules created by your detector.
