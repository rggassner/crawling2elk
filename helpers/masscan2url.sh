#!/bin/bash

# CONFIGURATION
NETWORK="10.0.0.0/8"
PORTS="80,443"
RATE=1500
OUTPUT_FILE="masscan_results.gnmap"
URLS_FILE="urls.txt"

# Check if masscan is installed
if ! command -v masscan &> /dev/null; then
    echo "Error: masscan is not installed. Please install it and retry."
    exit 1
fi

echo "[*] Starting masscan on $NETWORK ports $PORTS at rate $RATE packets/sec"

# Run masscan
sudo masscan $NETWORK -p$PORTS --rate=$RATE -oG "$OUTPUT_FILE"

if [[ $? -ne 0 ]]; then
    echo "[!] Masscan failed. Check your configuration."
    exit 1
fi

echo "[*] Masscan complete. Parsing results..."

# Parse masscan output into URL list
grep 'Ports:' "$OUTPUT_FILE" | \
awk '
/80\/open/ { print "http://" $2 }
/443\/open/ { print "https://" $2 }
' | sort -u > "$URLS_FILE"

echo "[*] Parsing complete. Output saved to $URLS_FILE"

# Report number of results
NUM_RESULTS=$(wc -l < "$URLS_FILE")
echo "[*] Found $NUM_RESULTS unique URLs."

echo "[*] Done."

