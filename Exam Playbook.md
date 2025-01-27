# Complete Network Penetration Testing Playbook

## Phase 1: Information Gathering & OSINT

### Primary Goals
- Build target profile
- Identify potential entry points
- Discover external attack surface
- Collect credential data

### Intelligence Collection (Priority Order)
1. **Network Information**
   - IP ranges
   - Domain names
   - ASN information
   - Network topology

2. **Technology Stack**
   - External services
   - Web technologies
   - Email systems
   - Remote access solutions

3. **Organization Intel**
   - Employee information
   - Email formats
   - Department structure
   - Job postings (tech stack hints)

4. **Credential Hunting**
   - Breach data analysis
   - Public password dumps
   - Code repositories
   - Public file shares

### Success Criteria
- Complete external network map
- Valid employee email list
- Potential password patterns
- Technology stack identified

## Phase 2: External Attack Surface

### Primary Goals
- Identify vulnerable services
- Discover authentication portals
- Find potential entry points
- Test discovered credentials

### Attack Surface Mapping
1. **Service Enumeration**
   - Port scanning
   - Service fingerprinting
   - SSL/TLS analysis
   - Public vulnerability scanners

2. **Web Application Discovery**
   - Virtual host enumeration
   - Directory bruteforcing
   - API endpoint discovery
   - Framework identification

3. **Authentication Portal Testing**
   - O365/Azure presence
   - VPN endpoints
   - Web mail systems
   - Admin interfaces

### Initial Access Vectors (Priority Order)
1. **Low-Hanging Fruit**
   - Default credentials
   - Common misconfigurations
   - Known CVEs
   - Public exploits

2. **Credential Attacks**
   - Password spraying
   - Credential stuffing
   - MFA bypass attempts
   - Token manipulation

3. **Application Attacks**
   - Web vulnerabilities
   - Service exploits
   - Configuration errors
   - Logic flaws

### Success Criteria
- Initial internal access
- Valid domain credentials
- Remote system access
- Foothold established

## Phase 3: Internal Network Attack

### Primary Goals
- Expand network access
- Gather internal intel
- Move laterally
- Identify AD presence

### Attack Progression
1. **Post-Exploitation**
   - Local enumeration
   - Privilege escalation
   - Credential harvesting
   - Persistence establishment

2. **Network Discovery**
   - Internal service mapping
   - Network segmentation
   - Trust relationships
   - Critical assets location

3. **Lateral Movement**
   - Pass-the-hash
   - Token stealing
   - Service impersonation
   - Remote execution

### Success Criteria
- Multiple system access
- Local admin privileges
- Internal network map
- Domain reconnaissance

## Phase 4: Active Directory Attack

### Primary Goals
- Gain domain user access
- Escalate to domain admin
- Establish domain persistence
- Extract valuable data

### Attack Paths (Priority Order)
1. **Initial Domain Compromise**
   - LLMNR/NBT-NS Poisoning
   - SMB Relay
   - Password Spraying
   - Service Exploitation

2. **Privilege Escalation**
   - Kerberoasting
   - AS-REP Roasting
   - Token Impersonation
   - ACL Abuse

3. **Domain Dominance**
   - DCSync
   - Golden Tickets
   - Silver Tickets
   - Domain Backdoors

### Success Criteria
- Domain Admin access
- Multiple persistence mechanisms
- Critical data acquired
- Complete domain compromise

### Attack Progression Specifics

1. **Initial Access to Domain Admin Path**
   ```
   Initial Access -> Local Admin -> Domain User -> Domain Admin
   ```

2. **Hash Exploitation Path**
   ```
   NTLMv2 (Responder) -> Crack/Relay -> NTLM (SAM dump) -> Pass-the-Hash
   ```

### Technical Progression Strategy

1. **Password Attack Flow**
   - Capture NTLMv2 with Responder
   - Crack hashes for initial access
   - Use compromised access to dump SAM
   - Leverage NTLM hashes for lateral movement

2. **Network Attack Flow**
   - Identify SMB signing configuration
   - Set up relay attacks
   - Capture and relay authentication
   - Dump local credentials

3. **Post-Compromise Flow**
   - Enumerate with BloodHound
   - Identify quick win paths
   - Execute privilege escalation
   - Establish persistence

### Domain Dominance Strategy

1. **Quick Win Checklist**
   - Kerberoasting attempts
   - Token impersonation
   - GPP password checks
   - Service account abuse

2. **Persistence Checklist**
   - NTDS.dit extraction
   - Golden ticket creation
   - Machine persistence
   - Alternative access paths

### Critical Technical Considerations
1. **Hash Type Awareness**
   - NTLMv2: Responder captures, needs cracking
   - NTLM: SAM dumps, usable for pass-the-hash
   - Kerberos: TGS tickets, service account hashes

2. **Authentication Flow**
   - WDigest: Clear text potential on legacy systems
   - NTLM: Pass-the-hash opportunities
   - Kerberos: Ticket attacks

## Phase 5: Post-Exploitation

### Primary Goals
- Document access methods
- Secure persistent access
- Extract valuable data
- Prepare for cleanup

### Key Activities
1. **Data Collection**
   - Password dumps
   - Configuration files
   - Sensitive documents
   - Network diagrams

2. **Persistence**
   - Backdoor accounts
   - System backdoors
   - Alternate access methods
   - Stealth mechanisms

3. **Documentation**
   - Attack paths
   - Successful techniques
   - System modifications
   - Created artifacts

### Success Criteria
- Complete attack documentation
- Multiple access methods
- Valuable data secured
- Clean-up plan ready

## Phase 6: Clean-up & Reporting

### Primary Goals
- Remove attack artifacts
- Restore system states
- Document findings
- Prepare deliverables

### Clean-up Process
1. **Artifact Removal**
   - Created accounts
   - Deployed tools
   - Backdoor access
   - Modified configs

2. **Documentation Review**
   - Attack paths
   - Successful techniques
   - Failed attempts
   - Discovered vulnerabilities

3. **Report Preparation**
   - Executive summary
   - Technical findings
   - Remediation steps
   - Evidence packets

### Success Criteria
- Clean system state
- Complete documentation
- Professional report
- Actionable findings

## Critical Success Factors

### Strategy
1. Always maintain multiple attack paths
2. Prioritize stealth over speed
3. Document everything in real-time
4. Verify findings before proceeding

### Common Pitfalls
1. Rushing to exploit without enumeration
2. Single path dependence
3. Poor documentation
4. Noisy tool usage
5. Incomplete clean-up

### Risk Management
1. Validate exploit impact before use
2. Monitor system stability
3. Maintain restoration points
4. Keep detailed change logs

## Emergency Procedures
1. **Attack Detection**
   - Cease current activities
   - Document current state
   - Contact client liaison
   - Await further instructions

2. **System Impact**
   - Stop impacting activities
   - Document the incident
   - Attempt restoration
   - Report to client

Remember:
- Patience and thorough enumeration are key
- Document everything in real-time
- Maintain multiple attack paths
- Always have a cleanup plan
- Think before you act
- Quality over quantity in findings
