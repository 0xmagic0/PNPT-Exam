# PNPT Study Guide: OSINT Reference

## Table of Contents
1. [Core OSINT Concepts](#core-osint-concepts)
2. [Search Engine Intelligence](#search-engine-intelligence)
3. [People & Identity Research](#people--identity-research)
4. [Password Intelligence](#password-intelligence)
5. [Social Media Intelligence](#social-media-intelligence)
6. [Website Reconnaissance](#website-reconnaissance)
7. [Image & Location Intelligence](#image--location-intelligence)
8. [Business Intelligence](#business-intelligence)
9. [Automation & Tools](#automation--tools)
10. [OPSEC & Ethics](#opsec--ethics)

## Core OSINT Concepts

### OSINT Lifecycle
1. Planning and Direction
2. Collection
3. Processing and Exploitation
4. Analysis and Production
5. Dissemination and Integration

### Key Principles
- Focus on publicly accessible information
- Document findings systematically
- Verify information across multiple sources
- Maintain OPSEC throughout investigation

## Search Engine Intelligence

### Advanced Search Operators
- Google Advanced Search: `site:`, `filetype:`, `inurl:`, `intitle:`
- Bing Advanced Operators
- DuckDuckGo Syntax
- Yandex Visual Search

### Key Search Engines
- Google (`https://www.google.com/advanced_search`)
- Bing
- Yandex
- DuckDuckGo
- Baidu (Chinese market)

## People & Identity Research

### Email Discovery
- Tools:
  - Hunter.io
  - Phonebook.cz
  - VoilaNorbert
  - Clearbit Connect (Chrome extension)

### Email Verification
```bash
# Use verification tools
emailhippo # https://tools.verifyemailaddress.io/
email-checker # https://email-checker.net/validate
```

### People Search Resources
- WhitePages
- TruePeopleSearch
- FastPeopleSearch
- WebMii
- PeekYou
- Spokeo
- That'sThem

### Phone Number Intelligence
```bash
# Phone number reconnaissance
phoneinfoga scan -n <number>
phoneinfoga serve -p 8080
```

### Voter Records
- VoterRecords.com
- State-specific databases

## Password Intelligence

### Breach Data Resources
- HaveIBeenPwned (Free)
  - Email/domain breach checking
  - Password breach verification
- Scylla.sh (Free)
  - Historical breach database
  - Raw data search capabilities

### Commercial Data Aggregators
- DeHashed
- LeakCheck
- SnusBase
- WeLeakInfo

### Search Techniques
- Google dorks for exposed credentials
- Historical data archives
- Hash lookup services (hashes.org)

## Social Media Intelligence

### Platform-Specific Tools

#### Twitter/X
- Advanced Search: `https://x.com/search-advanced`
- Search operators
- OSINT tools collection: `github.com/rmdir-rp/OSINT-twitter-tools`

#### Facebook
- Sowsearch.info
- IntelligenceX Facebook Search

#### Instagram
- ImgInn
- Profile ID extraction (View page source, search "profilePage_")

#### LinkedIn
- Company research
- Employee enumeration
- Job posting analysis

### Username Research
```bash
# Username enumeration
sherlock <username>
```

Tools:
- NameChk
- WhatsMyName
- NameCheckup

## Website Reconnaissance

### Domain Intelligence
```bash
# Basic domain reconnaissance
whois <domain>
subfinder -d <domain>
assetfinder <domain>
amass enum -d <domain>
```

### Tools & Resources
- BuiltWith
- Domain Dossier
- DNSlytics
- SpyOnWeb
- VirusTotal
- DNSdumpster
- crt.sh
- Shodan

### Automation Script
```bash
#!/bin/bash
domain=$1
base_dir="$domain"
mkdir -p "$base_dir"/{info,subdomains,screenshots}

# Reconnaissance sequence
whois "$domain" > "$base_dir/info/whois.txt"
subfinder -d "$domain" > "$base_dir/subdomains/found.txt"
assetfinder "$domain" | grep "$domain" >> "$base_dir/subdomains/found.txt"
cat "$base_dir/subdomains/found.txt" | httprobe -prefer-https > "$base_dir/subdomains/alive.txt"
gowitness file -f "$base_dir/subdomains/alive.txt" -P "$base_dir/screenshots/"
```

## Image & Location Intelligence

### Image Analysis
- Reverse Image Search:
  - Google Images
  - Yandex
  - TinEye

### EXIF Data Analysis
```bash
# Extract EXIF data
exiftool <image_file>
```

### Geolocation Tools
- GeoGuessr
- Google Maps
- Satellite imagery analysis
- Drone reconnaissance (where legal)

## Business Intelligence

### Resources
- OpenCorporates
- AI HIT
- LinkedIn company research
- Employee OSINT

## Automation & Tools

### Core Tools
```bash
# Essential OSINT tools
subfinder # Subdomain enumeration
assetfinder # Asset discovery
httprobe # Probe for HTTP/HTTPS services
amass # Attack surface mapping
gowitness # Web screenshot utility
```

### Framework Integration
- recon-ng
- Maltego
- Hunchly

## OPSEC & Ethics

### Sock Puppet Creation
- Essential for anonymous research
- Never link to personal accounts/identity
- Use separate VM/environment
- Implement strong privacy controls

### Key OPSEC Principles
1. Maintain separation from personal identity
2. Use dedicated research environment
3. Implement proper VPN/proxy configuration
4. Regular environment cleaning
5. Document findings securely

### Report Writing
- Executive Summary
- Key Findings
- Technical Evidence
- Documentation
- Recommendations

## Common Pitfalls
- ⚠️ Mixing personal and research identities
- ⚠️ Inadequate source verification
- ⚠️ Poor documentation practices
- ⚠️ Insufficient OPSEC measures
- ⚠️ Overlooking basic information sources

## Additional Resources
- OSINT Framework
- OSINT Techniques
- Digital Forensics Tools
- Privacy Tools
