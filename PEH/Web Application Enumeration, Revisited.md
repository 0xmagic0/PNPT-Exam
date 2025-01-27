# Introduction
This is going to be focused on tools written in go and linking all of them together
# Installin Golang
This was installed when we ran `pimpmykali`
# Assetfinder
Made by tomnomnom
Comes with kali linux
Basic usage
```bash
assetfinder tesla.com >> tesla-subs.txt
```
Limit results to only direct subdomains and exclude related websites
```bash
assetfinder --subs-only tesla.com >> tesla-subs.txt
```
# Subfinder
Comes with kali linux
Not mentioned in the course but it's written in go and is made by the great `projectdiscovery` team

# Amass
Made by OWASP
```bash
amass enum -d tesla.com
```
# Httprobe
Made by tomnomnom
Comes with Kali Linux
Probe for https:443 only and remove the https:// and :443 from the output
```bash
cat domains.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443'
```

# gowitness
The tool takes a screenshot of a website
Comes with kali linux
Single website
```bash
gowitness single https://tesla.com
```

# Script resources
- [https://pastebin.com/MhE6zXVt](https://pastebin.com/MhE6zXVt)
- [https://github.com/Gr1mmie/sumrecon](https://github.com/Gr1mmie/sumrecon)
