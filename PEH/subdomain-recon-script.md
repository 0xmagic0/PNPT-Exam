```bash
#!/bin/bash

url=$1
if [ ! -d "$url" ];then
    mkdir $url
fi
if [ ! -d "$url/recon" ];then
    mkdir $url/recon
fi

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $url >> $url/recon/assetfinder-urls.txt
grep $1 $url/recon/assetfinder-urls.txt >> $url/recon/assetfinder-urls-parsed.txt
rm $url/recon/assetfinder-urls.txt

echo "[+] Harvesting subdomains with subfinder..."
subfinder -d $url >> $url/recon/subfinder-urls.txt
grep $1 $url/recon/subfinder-urls.txt >> $url/recon/subfinder-urls-parsed.txt
rm $url/recon/subfinder-urls.txt

# echo "[+] Harvesting subdomains with amass..."
# amass enum -d $url >> $url/recon/amass-urls.txt
# grep $1 $url/recon/amass-urls.txt >> $url/recon/amass-urls-parsed.txt
# rm $url/recon/amass-urls.txt
#
# Combine all parsed results into one file
cat $url/recon/*-urls-parsed.txt >> $url/recon/all-subdomains.txt

# Sort and remove duplicates, save to a new file
sort -u $url/recon/all-subdomains.txt > $url/recon/final-subdomains.txt

# Remove the intermediate combined file
rm $url/recon/all-subdomains.txt

# Show the total number of unique subdomains found
echo "[+] Total unique subdomains found: $(wc -l < $url/recon/final-subdomains.txt)"

# httprobe
echo "[+] Probing for live subdomains..."
cat $url/recon/final-subdomains.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' > $url/recon/live-subdomains.txt

# Show the results summary
total_subdomains=$(wc -l < $url/recon/final-subdomains.txt)
live_subdomains=$(wc -l < $url/recon/live-subdomains.txt)

echo "[+] Results Summary:"
echo "    - Total subdomains found: $total_subdomains"
echo "    - Live subdomains: $live_subdomains"

echo "[+] Scanning for open ports..."
nmap -iL $url/recon/live-subdomains.txt -T4 -oA $url/recon/nmap_results.txt

echo "[+] Scraping wayback data..."
cat $url/recon/live-subdomains.txt | waybackurls >> $url/recon/wayback_output.txt
sort -u $url/recon/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $url/recon/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback_params.txt
for line in $(cat $url/recon/wayback_params.txt);do echo $line'=';done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
for line in $(cat $url/recon/wayback_output.txt);do
    ext="${line##*.}"
    if [[ "$ext" == "js" ]]; then
        echo $line >> $url/recon/js_temp.txt
        sort -u $url/recon/js_temp.txt >> $url/recon/js_urls.txt
    fi
    if [[ "$ext" == "html" ]];then
        echo $line >> $url/recon/html_temp.txt
        sort -u $url/recon/html_temp.txt >> $url/recon/html_urls.txt
    fi
    if [[ "$ext" == "json" ]];then
        echo $line >> $url/recon/json_temp.txt
        sort -u $url/recon/json_temp.txt >> $url/recon/json_urls.txt
    fi
    if [[ "$ext" == "php" ]];then
        echo $line >> $url/recon/php_temp.txt
        sort -u $url/recon/php_temp.txt >> $url/recon/php_urls.txt
    fi
    if [[ "$ext" == "aspx" ]];then
        echo $line >> $url/recon/aspx_temp.txt
        sort -u $url/recon/aspx_temp.txt >> $url/recon/aspx_urls.txt
    fi
done

# Cleanup temporary files
rm $url/recon/*_temp.txt
```
