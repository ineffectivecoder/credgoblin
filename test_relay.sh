#!/bin/bash
# Test script to validate credgoblin relay server is listening and accepting connections

set -e

RELAY_IP="${1:-127.0.0.1}"
echo "[*] Testing credgoblin relay server at $RELAY_IP"
echo ""

# Test port 445 (SMB)
echo "[*] Testing SMB port (445)..."
if timeout 2 nc -zv "$RELAY_IP" 445 2>&1 | grep -q "succeeded\|open"; then
    echo "[+] Port 445 is OPEN and accepting connections"
else
    echo "[-] Port 445 is CLOSED or unreachable"
    echo "    Make sure credgoblin is running with: sudo ./credgoblin relay -p 445 ..."
fi
echo ""

# Test port 80 (HTTP)
echo "[*] Testing HTTP port (80)..."
if timeout 2 nc -zv "$RELAY_IP" 80 2>&1 | grep -q "succeeded\|open"; then
    echo "[+] Port 80 is OPEN and accepting connections"
    
    # Try to send an HTTP request
    echo "[*] Sending test HTTP request..."
    if timeout 2 curl -s -o /dev/null -w "%{http_code}" "http://$RELAY_IP/test" 2>/dev/null | grep -q "401"; then
        echo "[+] Server responded with 401 (expected for NTLM auth)"
    else
        echo "[*] Server responded (check credgoblin logs for details)"
    fi
else
    echo "[-] Port 80 is CLOSED or unreachable"
    echo "    Make sure credgoblin is running with: sudo ./credgoblin relay -p 80 ..."
fi
echo ""

echo "[*] Testing complete!"
echo ""
echo "If ports are open but PetitPotam doesn't work, check:"
echo "  1. Firewall rules (iptables -L -n)"
echo "  2. Target can reach this IP ($RELAY_IP)"
echo "  3. Run credgoblin with -v for verbose logging"
echo "  4. Check target isn't blocking outbound SMB/HTTP"
