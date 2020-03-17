#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auther: 2020, Mayed Alm
# NstatResolver: Resolve IP addresses in NstatLogger log file along with dns history
# version: 1.1

import os
import re
import ssl
import sys
import json
import socket
import requests
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
from requests.packages.urllib3.contrib import pyopenssl as reqs

class NstatResolver:
    
    banner = ''' 
    _   __     __        __  ____                  __               
   / | / /____/ /_____ _/ /_/ __ \___  _________  / /   _____  _____
  /  |/ / ___/ __/ __ `/ __/ /_/ / _ \/ ___/ __ \/ / | / / _ \/ ___/
 / /|  (__  ) /_/ /_/ / /_/ _, _/  __(__  ) /_/ / /| |/ /  __/ /    
/_/ |_/____/\__/\__,_/\__/_/ |_|\___/____/\____/_/ |___/\___/_/     
                                                v1.1    ©Mayed.alm    
                                     
            '''
    
    def __init__(self):
        print(self.banner)
        if len(sys.argv) < 2:
            ip_input = input("Enter hostname/IP: ")
            self.reslove_func_ip(ip_input)
        elif len(sys.argv) > 2:
            sys.exit(input('ERROR: Supply one log file at once! Press Enter to exit'))
        self.reslove_func(sys.argv[1])
        
           
    def reslove_func(self,filename): #func to performe reverse ip lookup and dns history/ ssl alt names
        templ2 = '%-20s %-20s %-60s %-20s'
        filename = os.path.basename(filename)
        ipLst = []
        dns_alt_names = []
        try:
            choice = int(input('Choose option:\n 1) Search for DNS history through Threat Crowd API (recommended).\
            \n 2) Get SSL certificate alternative names (not recommended for suspecious connections as it connects to each IP).\n:'))
        except ValueError:
            sys.exit('Unknown option!')
        if not filename.startswith('NstatLogger'):
            sys.exit('ERROR: Unable to read file, make sure it\'s an NstatLogger log file!')
        with open(filename, 'rt') as fin:
            if os.path.isfile('Resolved-'+filename):
                sys.exit('\nWarning: Resolved file exists! delete or move to another directory')
            with open('Resolved-'+filename, 'w') as fout:
                if choice == 1:
                    fout.write(templ2 % ('Program name', 'Remote address', 'Domain name', 'DNS history') + '\n')
                elif choice == 2:
                    fout.write(templ2 % ('Program name', 'Remote address', 'Domain name', 'SSL alternative names') + '\n')
                else:
                    sys.exit('Unknown option!')
                print('Resolving...')
                f = fin.readlines()
                f = f[3:-2]
                for line in f:
                    ip = line[27:47]
                    ip = ip.split(':')
                    prog_name = line[75:95]
                    revers_lookup = {}
                    notFound = '-'
                    ip[0] = ip[0].replace(' ','')
                    if len(ip[0].strip()) == 0:
                        continue
                    if ip[0] in ipLst:
                        continue  
                    ipLst.append(ip[0])
                    try:
                        revers_lookup.update({ip[0]: socket.gethostbyaddr(ip[0])})                
                    except (socket.herror, socket.gaierror, OSError):
                        revers_lookup.update({ip[0]: notFound})
                    
                    if choice == 1:
                        threat_crowdAPI = requests.get("http://www.threatcrowd.org/searchApi/v2/ip/report/", {"ip": ip[0]})
                        threat_crowdJSON = json.loads(threat_crowdAPI.text)
                        try:
                            fout.writelines(templ2 % (f'{prog_name}', f'{ip[0]}', f'{revers_lookup[ip[0]][0]}', f"{threat_crowdJSON['resolutions'][::-1]}") + '\n')
                        except KeyError:
                            fout.writelines(templ2 % (f'{prog_name}', f'{ip[0]}', f'{revers_lookup[ip[0]][0]}', '-') + '\n')
                            continue
                    elif choice == 2:
                        try:
                            x509 = reqs.OpenSSL.crypto.load_certificate(
                                    reqs.OpenSSL.crypto.FILETYPE_PEM,
                                    reqs.ssl.get_server_certificate((ip[0], 443)))
                            dns_alt_names = reqs.get_subj_alt_name(x509)
                            fout.writelines(templ2 % (f'{prog_name}', f'{ip[0]}', f'{revers_lookup[ip[0]][0]}', f'{dns_alt_names}') + '\n')
                        except (socket.gaierror,ssl.SSLError,TimeoutError,ConnectionRefusedError,OSError):
                            fout.writelines(templ2 % (f'{prog_name}', f'{ip[0]}', f'{revers_lookup[ip[0]][0]}', '-') + '\n') 
                            continue
        return revers_lookup

    
    def reslove_func_ip(self,ip): #func to performe reverse ip lookup and dns history/ ssl alt names
        templ2 = '%-20s %-60s %-20s'
        ipv4 = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        match_ip = ipv4.match(ip)
        try:
            choice = int(input('Choose option:\n 1) Search for DNS history through Threat Crowd API (recommended).\
            \n 2) Get SSL certificate alternative names (not recommended for suspecious connections as it connects to each IP).\n:'))
        except ValueError:
            sys.exit('Unknown option!')
        with open('Resolved-'+ip+".txt", 'w') as fout:
            if choice == 1:
                fout.write(templ2 % ('Remote host', 'Domain name/IP', 'DNS history') + '\n')
            elif choice == 2:
                fout.write(templ2 % ('Remote host', 'Domain name/IP', 'SSL alternative names') + '\n')
            else:
                sys.exit('Unknown option!')
            print('Resolving...')
            notFound = '-'
            if match_ip:
                try:
                    revers_lookup = (socket.gethostbyaddr(ip))            
                except (socket.herror, socket.gaierror, OSError):
                    revers_lookup = notFound
            else:
                try:
                    revers_lookup = (socket.gethostbyname(ip))            
                except (socket.herror, socket.gaierror, OSError):
                    revers_lookup = notFound            
            if choice == 1:
                threat_crowdAPI = requests.get("http://www.threatcrowd.org/searchApi/v2/ip/report/", {"ip": ip})
                threat_crowdJSON = json.loads(threat_crowdAPI.text)
                try:
                    fout.writelines(templ2 % (f'{ip}', f'{revers_lookup}', f"{threat_crowdJSON['resolutions'][::-1]}") + '\n')
                except KeyError:
                    fout.writelines(templ2 % (f'{ip}', f'{revers_lookup}', '-') + '\n')
            elif choice == 2:
                try:
                    x509 = reqs.OpenSSL.crypto.load_certificate(
                            reqs.OpenSSL.crypto.FILETYPE_PEM,
                            reqs.ssl.get_server_certificate((ip, 443)))
                    dns_alt_names = reqs.get_subj_alt_name(x509)
                    fout.writelines(templ2 % (f'{ip}', f'{revers_lookup}', f'{dns_alt_names}') + '\n')
                except (socket.gaierror,ssl.SSLError,TimeoutError,ConnectionRefusedError,OSError):
                    fout.writelines(templ2 % (f'{ip}', f'{revers_lookup}', '-') + '\n') 
        return revers_lookup        
    

def main():
    try:
        n = NstatResolver()
    except IndexError:
        input("Done!, press enter to continue . . .")
if __name__=='__main__':
        main()
    
    
