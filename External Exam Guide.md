# External Penetration Testing Reference Guide

## 1. Fundamentals & Preparation

### Objectives
- Test security from an external perspective
- Identify potential vulnerabilities and security gaps
- Document issues that could lead to compromise
- Verify security controls effectiveness
- Focus on realistic attack scenarios

### Pre-Engagement
- Review and document Rules of Engagement (RoE)
- Verify scope thoroughly:
  - Confirm target IP ranges
  - Validate domain ownership
  - Use `bgp.he.net` for additional verification
- Create engagement tracking sheets for:
  - Password spraying attempts
  - Discovered credentials
  - Scope boundaries
  - Timeline tracking

## 2. Methodology

### Phase 1: Reconnaissance
1. **Initial Scanning**
   - Deploy Nessus Advanced Scanning
   - Run scans while conducting OSINT
   - Export and parse results using melcara.com parser

2. **OSINT Collection**
   - Employee enumeration:
     - `phonebook.cz`
     - `https://intelx.io/`
     - LinkedIn research
   - Technology stack investigation:
     - Review job postings
     - Identify used technologies
     - Document potential attack vectors

3. **Credential Research**
   - Tools:
     - `breach-parse`
     - dehashed website
   - Focus on:
     - Email formats
     - Username patterns
     - Historical breaches
   - Document findings for later testing

### Phase 2: Attack Strategy

1. **Initial Approach**
   - Focus on "low-hanging fruit"
   - Prioritize quick wins
   - External perspective focus
   - Web application testing through external context

2. **Common Attack Vectors**
   - Password patterns to test:
     ```
     Season+Year+Special
     City+Year
     SportsTeam+Year
     Company+Year
     ```

3. **Portal Attacks**
   - **O365 Testing:**
     - Tool: `TREVORspray`
     - Multiple IP rotation via AWS EC2
     - Document lockout policies

   - **OWA Testing:**
     - Use Metasploit module: `scanner/http/owa_login`
     - Monitor for lockouts

   - **MFA Bypass Attempts:**
     - Tool: `dafthack/MFASweep`
     - Focus on misconfigurations
     - Document bypass attempts

## 3. Common Findings

### Authentication Issues
- Missing MFA implementation
- Weak password policies
- Default credentials
- Username enumeration
- Account compromise history

### Infrastructure Vulnerabilities
- Insufficient patching (CVEs)
- Exposed services:
  - RDP
  - Telnet
  - Mail relays
- IKE Aggressive Mode
- Weak encryption:
  - HTTP exposure
  - Outdated SSL/TLS

### Information Disclosure
- Verbose error messages
- Server response headers
- Default web pages
- Job posting information leaks

## 4. Documentation & Reporting

### Report Structure
1. Front page
2. Table of Contents
3. Confidentiality Statements
4. Assessment Overview
5. Components Tested
6. Executive Summary
7. Detailed Findings

### Post-Engagement
- Client debriefs (educational approach)
- Attestation letters
- Retest scheduling
- Findings verification

## Key Tips
- **Always Enumerate**: The three most important steps are enumerate, enumerate, enumerate
- **OPSEC First**: Maintain careful documentation of all testing
- **Think External**: Maintain external perspective throughout testing
- **Timeline Management**: Days 1-2 should focus on research and reconnaissance
- **Documentation**: Keep detailed logs of all testing activities

## Tools Quick Reference
```markdown
Reconnaissance:
- Nessus Advanced Scanner
- breach-parse
- phonebook.cz
- intelx.io

Attack:
- TREVORspray
- Metasploit OWA Scanner
- MFASweep
- Burp Suite

Verification:
- bgp.he.net
- Shotsherpa
```
