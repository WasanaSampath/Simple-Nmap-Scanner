#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("This is a simple nmap automation tool")
print("--------------------------------------")

ip_addr = input("Please enter IP address to scan")
print("The IP you entereed is: ", ip_addr)
type(ip_addr) 
resp = input("""\nPlease enter the type of scan you want to perform
             
             1) SYN Ack Scan
             2) UDP Scan
             3) Comprehensive Scan 
             \n""")
print("You have selected: ",resp)
if resp == '1':
    print("Nmap Version:",scanner.nmap_version)
    scanner.scan(ip_addr,'1-1024','-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports are: ",scanner[ip_addr]['tcp'].keys())

elif resp == '2':
    print("Nmap Version:",scanner.nmap_version)
    scanner.scan(ip_addr,'1-1024','-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports are: ",scanner[ip_addr]['udp'].keys())

elif resp == '3':
    print("Nmap Version:",scanner.nmap_version)
    scanner.scan(ip_addr,'1-1024','-v -sU -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports are: ",scanner[ip_addr]['tcp'].keys())

elif resp >='4' or resp <='0':
    print("Enter valid Option")
    


