!/bin/bash

date
zmap -i enp2s0 -M icmp_echoscan -l ipv4.txt
date
