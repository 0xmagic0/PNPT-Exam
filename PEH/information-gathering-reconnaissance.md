## Passive Reconnaissance Overview
- Target Validation
    - WHOIS
    - nslookup
    - dnsrecon
- Finding Subdomains
- Fingerprinting
- Data Breaches
## Discovering Email Addresses
- First use google to find people of interest
- Then use some of the websites below to find the person's email:
    - hunter.io
    - phonebook.cz
    - voilanorbert.com
    - clearbit (chrome extension)
- Verify the email address:
    - tools.verifyemailaddress.io
    - email-checker.net/validate
- Could also use "forgot password" functionality in google to discover an email address related to another one
## Gathering Breached Credentials with Breach-Parse
- [breach-parse - github tool](https://github.com/hmaverickadams/breach-parse)
- HaveIBeenPwned
- WeLeakInfo
## Hunting Breached Credentials with DeHashed (or a similar website, use the methodology)
- It costs money
- [dehashed.com](dehashed.com)
- Find one piece of information and try to tie it to another data point. Examples below
- Look for an email, and use that email to find an username, or password, or IP address, etc.
    - Email -> username.
    - Email -> password.
    - password -> different username.
    - password -> different email.
    - username -> password.
- Use hashes.org to search hashes
## Hunting Subdomains
- OWASP AMASS: takes long to install and configure, but is the most complete of the list
- sublist3r: Needs to be installed in Kali
- subfinder: Not mentioned in the video but faster than sublist3r
- [crt.sh website](https://crt.sh): Website that does certificate fingerprinting
- [httprobe](https://github.com/tomnomnom/httprobe): Tool to determine if a subdomain is live
## Identifying Website Technologies
- https://builtwith.com
- Wappalyzer - Chrome extension
- whatweb - CLI
## Information Gathering with Burp Suite
- Setup and overview
## Google Fu
- Google dorks. Might want to use a cheatsheet
- [Google Dorking For Pentesters: A Practical Guide](https://www.freecodecamp.org/news/google-dorking-for-pentesters-a-practical-tutorial/)
- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
    - site:domain.com
    - To exclude words use the minus `-` operator: site:domain.com -www
    - filetype:docx
- Google dorks might be able to disclose sensitive information
## Utilizing Social Media
- Linkedin: Employees' pictures disclosing info
- X (Formerly known as Twitter)
- Create bogus accounts
- Find names
- Guess email addresses
