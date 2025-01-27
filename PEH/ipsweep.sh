#!/bin/bash

if [ "$1" == "" ]
then
echo "You forgot an IP address"
echo "Syntax: ./ipsweep.sh 192.168.1"

else
for ip in `seq 1 254`; do
ping $1.$ip -c 1 | grep "64 bytes"|cut -d " " -f 4|tr -d ":" &
done
fi

# Example
# ./ipsweep.sh 192.168.1 > ips.txt
# Oneliner to use the output of the ips.txt file
# for ip in $(cat ips.txt); do nmap -oN $ip.txt -Pn -vv $ip & done
