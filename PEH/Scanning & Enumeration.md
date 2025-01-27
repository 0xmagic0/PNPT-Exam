# Scanning with Nmap
- netdiscover
```bash
sudo netdiscover
```
- arp-scan. Run an arp scan on the local network
```bash
sudo arp-scan -l
```
- nmap. For this course we will focus on the flags below and also `-sS` and `-sU`
```bash
# Quick
nmap -T4 -p- ip-address/range
# Not so quick
nmap -T4 -p- -A ip-address/range
# More targeted once open ports have been found
nmap -T4 -p 22,80,443 -A ip-address/range
# the -T4 is the speed
# -p- is for all ports
# -A is to perform -sV, -sC, and -O all together
# For UDP since we don't want to wait for hours, we will modifity to the one below.
nmap -sU -T4 -p ip-address/range
```
# Enumerating HTTP and HTTPS
- Look for low hanging fruits
- Make notes
- nikto: vulnerability scanner, good for ctfs
```bash
nikto -h https://domain.com
- Save the results of scans
```
- gobuster
- dirbuster
- ffuf <- Fastest
- Burp Suite
# SMB enumeration
- msfconsole
```bash
# keyword based search
search smb
# use a module
use path-or-number
# get relevant information about the module selected
options
# set a variable value
set variable value
```
- smbclient
```bash
# Linux Syntax
# List shares
smbclient -L \\\\ip-addr\\
# Connect
smbclient \\\\ip-addr\\Sharename$
```
# SSH enumeration
- Attempt to get the banner, if there is any
```bash
ssh ip-ad
# If no matching key exchange method found
ssh ip-ad -oKexAlgorithms=+algorithm-name-here
# If no cipher found
ssh ip-ad -oKexAlgorithms=+algorithm-name-here -c cipher-name-here
```
# Researching Potential Vulnerabilities
Find possible exploits corresponding to the ports and technologies we've enumerated
- Google: tech-name version exploit. Easy peasy lemon squeezy
- [exploit-db](www.exploit-db.com)
- GitHub
- Rapid7
No internet connection on the kali machine?  
- searchsploit. Don't be too specific as it is a string based search
```bash
searchsploit Samba 2
searchsploit mod ssl 2
```
# Vulnerability Scanning with Nessus
- Download on kali, activate account, and run a basic network scan
- Always verify the vulnerability, never trust a scanner
