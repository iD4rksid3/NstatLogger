#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auther: 2020, Mayed Alm
# NstatResolver: Resolve IP addresses in NstatLogger log file along with dns history
# version: 1.5

import os
import re
import ssl
import sys
import csv
from alive_progress import alive_bar
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
                                                v1.5    ©Mayed.alm    

            '''

    def __init__(self):
        self.vt_api_key = "" #Edit with your virus total API key
        print(self.banner)
        if len(sys.argv) < 2:
            ip_input = input("Enter hostname/IP: ")
            self.reslove_func_ip(ip_input)
        elif len(sys.argv) > 2:
            sys.exit(input('ERROR: Supply one log file at once! Press Enter to exit'))
        self.reslove_func(sys.argv[1])



    def reslove_func(self,filename): #func to performe reverse ip lookup and dns history/ ssl alt names
        filename_base_name = os.path.basename(filename)
        ip_list = []
        dns_alt_names = []
        prog_name_lst = []
        revers_lookup = {}
        notFound = '-'
        try:
            choice = int(input('Choose option:\n 1) Search for DNS history through Threat Crowd and VirusTotal APIs (recommended).\
            \n 2) Get SSL certificate alternative names (not recommended for suspecious connections as it connects to each IP).\n:'))
        except ValueError:
            sys.exit('Unknown option!')
        #if not filename.startswith('NstatLogger'):
            #sys.exit('ERROR: Unable to read file, make sure it\'s an NstatLogger log file!')
        with open(filename, 'r') as file_in:
            with open('Resolved-'+filename_base_name, 'w') as file_out_csv: #csv file out
                writer = csv.writer(file_out_csv)
                if choice == 1:
                    writer.writerows([('Program name','Remote address','Domain name','DNS history')]) 
                elif choice == 2:
                    writer.writerows([('Program name', 'Remote address', 'Domain name', 'SSL alternative names')])
                else:
                    sys.exit('Unknown option!')
                print('Resolving...')
                line_counter = 0
                for lines in file_in.readlines()[3:-2]:
                    try:
                        ip_addr = lines.split(',')[2]
                        ip_addr = ip_addr.rsplit(':',1)[0].strip() #get the ip only without the port
                        program_name = lines.split(',')[5] #get the program name
                    except:
                        continue
                    if ip_addr in ip_list:
                        continue
                    if lines.split(',')[2] == ' ': # ignoring program names with no remote ip address (e.g udp)
                        continue
                    else:
                        prog_name_lst.append(program_name) #append program names to the prog_name_lst
                        ip_list.append(ip_addr) #append ip addresses to the ip_list
                        line_counter += 1                     

                with alive_bar(line_counter) as bar:
                    for ip, prog in zip( ip_list,prog_name_lst):
                        try:
                            revers_lookup.update({ip: socket.gethostbyaddr(ip)})                
                        except (socket.herror, socket.gaierror, OSError):
                            revers_lookup.update({ip: notFound})
        
                        if choice == 1:
                            threat_crowdAPI = requests.get("http://www.threatcrowd.org/searchApi/v2/ip/report/", {"ip": ip})
                            threat_crowdJSON = json.loads(threat_crowdAPI.text)
                            vt_api = requests.get(f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={self.vt_api_key}&ip={ip}")
                            try:
                                vt_apiJSON = json.loads(vt_api.text)
                                writer.writerows([(prog, ip, revers_lookup[ip], vt_apiJSON['resolutions'], threat_crowdJSON['resolutions'][::-1])])
                                bar()
                            except:
                                pass
                                try:
                                    writer.writerows([(prog, ip, revers_lookup[ip], threat_crowdJSON['resolutions'][::-1])])
                                    bar()
                                except KeyError:
                                    writer.writerows([(prog, ip, revers_lookup[ip])])
                                    bar()
                                    continue
                        elif choice == 2:
                            try:
                                x509 = reqs.OpenSSL.crypto.load_certificate(
                                    reqs.OpenSSL.crypto.FILETYPE_PEM,
                                    reqs.ssl.get_server_certificate((ip, 443)))
                                dns_alt_names = reqs.get_subj_alt_name(x509)
                                writer.writerows([(prog, ip, revers_lookup[ip], dns_alt_names)])
                                bar()
                            except (socket.gaierror,ssl.SSLError,TimeoutError,ConnectionRefusedError,OSError):
                                writer.writerows([(prog, ip, revers_lookup[ip], '-')])
                                bar() 
                                continue
        return revers_lookup


    def reslove_func_ip(self,ip): #func to performe reverse ip lookup and dns history/ ssl alt names
        ipv4 = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        match_ip = ipv4.match(ip)
        try:
            choice = int(input('Choose option:\n 1) Search for DNS history through Threat Crowd and VirusTotal APIs (recommended).\
            \n 2) Get SSL certificate alternative names (not recommended for suspecious connections as it connects to each IP).\n:'))
        except ValueError:
            sys.exit('Unknown option!')
        with open('Resolved-'+ip.replace(':','')+".csv", 'w') as file_out_csv:
            writer = csv.writer(file_out_csv)            
            if choice == 1:
                writer.writerows([('Remote host', 'Domain name/IP', 'DNS history')]) 
            elif choice == 2:
                writer.writerows([('Remote host', 'Domain name/IP', 'SSL alternative names')])
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
                vt_api = requests.get(f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={self.vt_api_key}&ip={ip}")
                try:
                    vt_apiJSON = json.loads(vt_api.text)
                    writer.writerows([(ip, revers_lookup, vt_apiJSON['resolutions'], threat_crowdJSON['resolutions'][::-1])])
                except:
                    print("No or incorrect VT api key supplied")
                    try:
                        writer.writerows([(ip, revers_lookup, threat_crowdJSON['resolutions'][::-1])])
                        
                    except KeyError:
                        print("error")
                        writer.writerows([(ip, revers_lookup, '-')])
                        
            elif choice == 2:
                try:
                    x509 = reqs.OpenSSL.crypto.load_certificate(
                        reqs.OpenSSL.crypto.FILETYPE_PEM,
                        reqs.ssl.get_server_certificate((ip, 443)))
                    dns_alt_names = reqs.get_subj_alt_name(x509)
                    writer.writerows([(ip, revers_lookup, dns_alt_names)])
                    
                except (socket.gaierror,ssl.SSLError,TimeoutError,ConnectionRefusedError,OSError):
                    writer.writerows([(ip, revers_lookup, '-')])                    
        return revers_lookup        


if __name__=='__main__':
    try:
        n = NstatResolver()
    except IndexError:
        input("Done!, press enter to continue ...")
