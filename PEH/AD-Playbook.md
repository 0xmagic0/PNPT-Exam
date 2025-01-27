# Initial Attack Vectors
1. LLMNR Poisoning
   - Use responder -> Capture NTLMv2 hashes -> try to crack them
2. SMB Relay
   - SMB signing must be disabled or not enforced
   - Relay the captured hashes: nmap to identify vulnerable machines -> disable responder's SMB and HTTP -> Use responder and ntlmrelayx.py
   - Relayed user credentials must be admin (local admin) on the machine for any real value
   - This will dump the SAM hashes. Save them into a file
3. Gaining shell access
   - Use metasploit `/smb/psexec` -> We can use a password or a hash. Noisy method and might get picked up
   - Use `psexec.py` -> We can use a password or a hash. Not as noisy at metasploit
   - We use the whole hash, the NT and LM parts
   - Other tools to use in case the psexec doesn't work: `wmiexec` or `sbmexec`
4. IPv6 Attacks
   - IPv6 is enabled but not used
   - Use `mitm6`. We do MITM and we can use it to authenticate to the DC via LDAP or SMB
   - We will use ntlmrelayx.py
   - LDAPS Relay
   - When we run the attack we will see ipv6 addresses get assigned
   - When an event happens, we will be able to relay it to the domain controller
   - If an administrator logs in, this attack will create an user for us
   - This new user will have specific access for us to attempt a DCSync attack with secretsdump.py.
   - Once the secrets are dumped, we can use them to compromise the domain
5. Passback Attack
   - Printer with default credentials
   - Access the embedded web service (EWS)
   - Look for LDAP or SMB connections
   - Change the connection IP address from the DC to your machines IP
   - Setup a listener with netcat or responder
   - We get the password in cleartext
6. Strategy
   - Begin with responder
   - Might also use mitm6 if things are rough
   - Run scans to generate traffic
   - If scans take too long, look for websites in scope (nmap or metasploit:http_version)
```bash
nmap -sV -p80,443,8000,8080,8443 --open -T4 <target_range> -oA webapps
```
   - Look for default credentials in web logins
   - Think outside the box
# Post-Compromise AD Enumeration
1. ldapdomaindump
   - We need an username and password, or ntlm hash
2. Bloodhound
   - We want to run neo4j console (pre-requisite)
   - The default user and password is neo4j
   - Now we can run bloodhound
   - We want to collect data first. We will use an ingestor
   - Run the ingestor
   - We can use a password or a hash
   - Import the data to bloodhound
   - We can now visualize the data, run analysis, and formulate plans
3. Plumphound
   - You need to have bloodhound running
   - Looks similar to ldapdomaindump
4. PingCastle
   - Windows tool. We need to run it as administrator
#  Post-Compromise Attacks
1. Pass Attacks
   - llmnr -> user hash -> cracked -> crackmapexed: spray the password -> found new login -> secretsdump those logins -> local admin hashes
   - respray the network with local accounts
   - Tool: crackmapexec - passwords and hashes
   - Tool: metasploit windows/smb/psexec - hashes
   - Tool: secretsdump.py - hashes - Need a local admin
   - Tool: cmedb - crackmapexec has a database with the data collected
   - both secretsdump.py and crackmapxec can be used to get sam hashes, enumerate shares, get lsa
   - crackmapexec has modules:
      - we could also use it to dump lsass
      - lsass stores credentials, if there is an active user we could dump credentials that we might not see from secretsdump.py
   - After running crackmapexec and determining what machines we have local admin access to, then we want to use secretsdump.py to dump secrets
      - Secretsdump gives the NTLM hashes. Do not confuse it with NTLMv2
   - We get the local admin hash or password and pass it around to get more access to other machines
   - use the local admin hash with secretsdump.py
   - Save the local administrator hash and any other user
   - If wdigest is enabled, we might get a password in clear text from secretsdump.py
   - WDigest is enabled by default on Windows 7, 8, Server 2008 R2, and Server 2012.
2. Kerberoasting
   - Tool: GetUserSPNs.py
   - Get request a TGT and then use it to get a TGS
   - The TGS has the service account hash
   - We attempt to crack that hash to get the service account's password
3. Token Impersonation
   - Tokens are like cookies for computers
   - We will target the delegate tokens
   - Tool: Metasploit > get shell with psexec > load "incognito" module
      - We will list tokens and impersonate tokens
      - In our labs we will impersonate the DA account
   - If we are able to impersonate other users like a domain admin we could use it to add a new user to the domain with domain admin permissions
```bat
net user /add hawkeye Password1@ /domain
net group "Domain Admins" hawkeye /ADD /DOMAIN
```
4. LNK File Attacks
- Placing a malicious file in a shared folder. Once an user sees the file in the share, we get a NTLMv2 hash
- We will name the file something that starts with `@` or `~`, such as `@test.lnk`. This is so it appears at the top of the folder
- Tool: Powershell. The script is provided in the course. We need to run powershell as an administrator
- Tool: netexec which is crackmapexec, but updated. We'll use the `slinky` module
- netexec: The set up in the course does not have the share expose, but this would work if the share was exposed.
- We use responder to capture the hash
5. GPP / cPassword Attacks
   - Older attack. Patched in MS14-025, but it might still be seen
   - Policies with embedded credentials. The credentials were encrypted. The key for these passwords was accidentally released
   - Tool: gpp-decrypt
   - Tool: Metasploit > smb_enum_gpp - We need credentials
6. Mimikatz
   - It will get picked up by any anti-virus. We need to obfuscated it in many ways
   - It can help view and steal credentials, generate Kerberos tickets, dump credentials in memory, pass-the-hash, etc.
   - Get the mimikatz files from github
   - Transfer them to the victim's machine
   - We'll need to run the .exe file as Administrator
   - In the course demo, we dumped credentials from memory
7. Post-Compromise Strategy
   - We have an account, now what?
   - Search for quick wins
      - Kerberoasting
      - Secretsdump
      - Pass the hash / pass the password
   - No quick wins? Dig deep!
      - Enumerate (Bloodhound, etc.)
      - Where does your account have access?
      - Old vulnerabilities die hard
   - Think outside the box
# We've compromised the domain, now what?
1. Post Domain Compromise Attack Strategy
   - Provide as much value to the client as possible
      - Try to do it again, but another way
      - Dump the NTDS.dit and crack passwords
      - Enumerate shares for sensitive information
   - Persistence can be important
      - What happens if our DA access is lost?
      - Creating a DA account can be useful (DO NOT FORGET TO DELETE IT)
      - Creating a Golden ticket can be useful, too
2. Dumping the NTDS.dit
   -  It's a database that stores AD data
   -  Use secretsdump.py against the domain controller using a domain admin account
   -  Get the hashes and try to crack them
3. Golden Ticket Attacks
   - When we compromise the krbtgt account (the TGT account), we own the domain. We can request access to any resource or system on the domain
   - Golden tickets == complete access to every machine
   - We need the krbtgt NTLM hash and the domain's sid
   - Tool: Mimikatz > lsadump > golden ticket > ptt for cmd.exe > run psexec.exe to get a shell in any machine
   - Tool: secretsdump.py against DC with DA account > Mimikatz > Golden ticket > ptt for cmd.exe > run psexec.exe to get a shell in any machine
