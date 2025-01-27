# Introduction
Post-Compromise AD Enumeration
What do we do once we have an account? Enumerate!
## Tools
- Bloodhound
- Plumhound
- Ldapdomaindump
- PingCastle
- Whatever else you want
# Domain Enumeration with ldapdoamindump
This tool was automatically used in the IPv6 relay attack
This tool is built into kali
Make a directory
```bash
mkdir Domain-Name
mkdir Marvel
```
inside that folder run the command
```bash
sudo ldapdomaindump ldaps://DC-IP -u 'username' -p 'Password' -o directory-mame # -o is optional if we have done the previous step of creating a directory
sudo ldapdomaindump ldaps://DC-IP -u 'MARVEL\fcastle' -p 'Password'
```
View the contents and find useful enumeration
# Domain Enumeration with Bloodhound
Very popular.
Install or Update the tool.
```bash
sudo apt update && sudo apt install -y bloodhound
# Start neo4j
sudo neo4j console
# default credentials are neo4j:neo4j
```
You will be prompted to change the password the first time you login.
After this, then bloodhound can be run.
```bash
sudo bloodhound
```
Once again, make a directory specific for the output and `cd` into it.
We need to use an ingester to collect data.
```bash
sudo bloodhound-python -d DOMAIN-Name -u user -p password -ns DC-IP -c all
sudo bloodhound-python -d MARVEL.local -u fcaslte -p password -ns DC-IP -c all
```
That command should have collected data.
Import that data into bloodhound.
Now we can use the tools to analyze and visualize the data.
# Domain Enumeration with Plumhound
[https://github.com/PlumHound/PlumHound](https://github.com/PlumHound/PlumHound)
Clone repo into the `/opt` folder.
```bash
git clone url
```
cd into the folder and install it
```bash
# python3 -m venv venv-name: Optional or required depending on kali
# source venv-name/bin/activate Optional or required depending on kali
sudo pip3 install -r requirements
```

Usage: NOTE - Bloodhound needs to be up and running
```bash
# Test
sudo python3 PlumHound.py --easy -p bloohound-passoword-here
# Real usage
sudo python3 PlumHound.py -x tasks/default.tasks -p bloohound-passoword-here # read the documentation for other tasks and flags
```
There should be a `reports` directory now. View the contents of it.
The `index.html` give easy access to the reports.
# Domain Enumeration with PingCastle
[www.pingcastle.com](www.pingcastle.com)
For this section just watch, no need to follow along.
It's a tool with a free side and a paid version.
Download it.
Run the .exe as Administrator.
View the ad_hc_domain-name.html file to see the report.
