#!/bin/bash

echo "[+] Checking for live domains..."
cat domains.txt | httprobe -p https:443 -s | sed 's/https\?:\/\///' | tr -d ':443' > live_domains.txt

# Show the results summary
total_domains=$(wc -l < domains.txt)
live_domains=$(wc -l < live_domains.txt)

echo "[+] Results Summary:"
echo "    - Total domains: $total_domains"
echo "    - Live domains: $live_domains"

echo "[+] Scanning for open ports with naabu..."
sudo naabu -l live_domains.txt -o ports.txt

echo "[+] Gathering web technology information with httpx..."
cat live_domains.txt | httpx-toolkit -status-code -tech-detect -title -web-server -method -websocket -ip -o httpx_results.txt

echo "[+] Fingerprinting web technologies with whatweb..."
whatweb -i live_domains.txt --log-json whatweb_results.json

echo "[+] Fingerprinting web technologies with nuclei..."
nuclei -list domains.txt -t technologies > nuclei_technologies.txt
echo "[+] Fingerprinting cves with nuclei..."
nuclei -list domains.txt -t cves > nuclei_cves.txt

echo ""
echo "[+] Scan complete! Check the following files for results:"
echo "    - live_domains.txt        (Live domains)"
echo "    - ports.txt               (Port scan results)"
echo "    - httpx_results.txt       (Web technology details)"
echo "    - nuclei_technologies.txt (Web technology details)"
echo "    - nuclei_cves.txt         (Web technology details)"
