#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auther: 2021, Mayed Alm
# NstatResolver: Resolve IP addresses in NstatLogger log file along with dns history
# version: 2.0

import os
import ssl
import sys
import csv
import socket
import binascii
import asyncio
import aiodns
import aiohttp
import configparser
from requests.packages.urllib3.contrib import pyopenssl as reqs


class NstatResolver:
    
    banner = '''
    _   __     __        __  ____                  __
   / | / /____/ /_____ _/ /_/ __ \___  _________  / /   _____  _____
  /  |/ / ___/ __/ __ `/ __/ /_/ / _ \/ ___/ __ \/ / | / / _ \/ ___/
 / /|  (__  ) /_/ /_/ / /_/ _, _/  __(__  ) /_/ / /| |/ /  __/ /
/_/ |_/____/\__/\__,_/\__/_/ |_|\___/____/\____/_/ |___/\___/_/
                                                v2.0    ©Mayed.alm

            '''

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')        
        self.vt_api_key = config["API_KEY"]["virus_total"]  # Edit config file with your virus total API key.
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop)        
        print(self.banner)
        if len(sys.argv) < 2:
            sys.exit(
                input("[!] Usage: python3 NstatResolver.py NstatLogger-00-00-00.csv"))
        elif len(sys.argv) > 2:
            sys.exit(
                input("[!] Usage: python3 NstatResolver.py NstatLogger-00-00-00.csv"))
        self.reslove_func(sys.argv[1])
        
         
    def choice(self):
        try:
            self.choice = int(
                input('Choose option:\n 1) Search for DNS history through Threat Crowd and VirusTotal APIs (recommended).\
            \n 2) Get SSL certificate alternative names (not recommended for suspecious connections as it connects to each IP).\n:'))
        except ValueError:
            sys.exit('Unknown option!')
        except  KeyboardInterrupt:
            exit('\nExiting..')
        if self.choice == 1:
            self.choose_1 = [('Program name', 'Remote address', 'Domain name', 'DNS history')]
            self.choose_2 = []
        elif self.choice == 2:
            self.choose_1 = []
            self.choose_2 = [('Program name', 'Remote address', 'Domain name', 'SSL alternative names')]
        else:
            sys.exit('Unknown option!')        
        return self.choice, self.choose_1, self.choose_2
            
    async def query(self, name, query_type):
        try:
            return await self.resolver.gethostbyaddr(name)
        except ValueError:
            return await self.resolver.gethostbyname(name, socket.AF_INET)
        except aiodns.error.DNSError:
            return await "Domain not found"        
    
    async def fetch(self, session, url):
        async with session.get(url) as self.response:
            return await self.response.text()
    
    async def fetch_all(self, urls, loop):
        async with aiohttp.ClientSession(loop=loop) as session:
            self.results = await asyncio.gather(*[self.fetch(session, url) for url in urls], return_exceptions=True)
            return self.results
            
            
    # func to performe reverse ip lookup and dns history/ ssl alt names
    def reslove_func(self, filename):
        filename_base_name = os.path.basename(filename)
        try:
            with open(filename, "rb") as f:
                header = f.read(4)
                header = binascii.hexlify(header)
        except FileNotFoundError:
            exit("[!] File not found!")
        if header != b'50726f74':
            exit("ERROR: make sure it is NstatLogger log file")
        ip_list = []
        dns_alt_names = []
        prog_name_lst = []
        revers_lookup = {}
        not_found = '-'
        choice, choose_1, choose_2 = self.choice()    
        with open(filename, 'r') as file_in:
            with open('Resolved-' + filename_base_name, 'w') as file_out_csv:  # csv file out
                writer = csv.writer(file_out_csv)
                if choice == 1:
                    writer.writerows(choose_1)
                elif choice == 2:
                    writer.writerows(choose_2)
                print('Resolving...')
                line_counter = 0
                for lines in file_in.readlines()[3:]: #maybe -2?
                    try:
                        ip_addr = lines.split(',')[2]
                        # get the ip only without the port
                        ip_addr = ip_addr.rsplit(':', 1)[0].strip()
                        program_name = lines.split(
                            ',')[5]  # get the program name
                    except BaseException:
                        continue
                    if ip_addr in ip_list:
                        continue
                    if lines.split(
                        ',')[2] == ' ':  # ignoring program names with no remote ip address (e.g udp)
                        continue
                    else:
                        # append program names to the prog_name_lst
                        prog_name_lst.append(program_name)
                        # append ip addresses to the ip_list
                        ip_list.append(ip_addr)
                        line_counter += 1
                  
                loop = asyncio.get_event_loop()
                queue = asyncio.gather(*(self.query(ip, -1) for ip in ip_list), return_exceptions=True)
                rev_lookup_result = loop.run_until_complete(queue)
                threat_crowd_api = [f"http://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}" for ip in ip_list]
                threat_crowd_response = loop.run_until_complete(self.fetch_all(threat_crowd_api, loop))
                if self.vt_api_key is not None:
                    vt_api = [f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={self.vt_api_key}&ip={ip}" for ip in ip_list]
                    vt_response = loop.run_until_complete(self.fetch_all(vt_api, loop))
                else:
                    vt_api = [not_found for ip in ip_list]                 
                for ip, prog, rev_resolve, tc, vt in zip(ip_list, prog_name_lst, rev_lookup_result, threat_crowd_response, vt_response):                          
                    indx_tc = tc.find('resolutions')
                    indx_start_vt = vt.find('resolutions')
                    indx_end_vt = vt.find('hashes')
                    try:
                        revers_lookup.update(
                            {ip: str(rev_resolve).split(",")[1]})
                    except (IndexError, OSError, ValueError, aiodns.error.DNSError):
                        revers_lookup.update({ip: not_found})

                    if choice == 1:
                            if self.vt_api_key is not None:
                                try:
                                    writer.writerows([(prog,
                                                   ip,
                                                   revers_lookup[ip],
                                                   tc[indx_tc:],
                                                   vt[indx_start_vt:indx_end_vt])])    
                                except BaseException:
                                    pass
                                                                
                            else:
                                try:
                                    writer.writerows([(prog, 
                                                       ip, 
                                                       revers_lookup[ip], 
                                                       tc[indx_tc:])])
                                except KeyError:
                                    writer.writerows(
                                        [(prog, 
                                          ip, 
                                          revers_lookup[ip])])
                                    continue                            

                    elif choice == 2:
                        try:
                            x509 = reqs.OpenSSL.crypto.load_certificate(
                                reqs.OpenSSL.crypto.FILETYPE_PEM,
                                reqs.ssl.get_server_certificate((ip, 443)))
                            dns_alt_names = reqs.get_subj_alt_name(x509)
                            writer.writerows(
                                [(prog, ip, revers_lookup[ip], dns_alt_names)])
                        except (socket.gaierror, ssl.SSLError, TimeoutError, ConnectionRefusedError, OSError):
                            writer.writerows(
                                [(prog, ip, revers_lookup[ip], '-')])
                            continue
        return revers_lookup    
    
     
if __name__ == '__main__':
    try:
        n = NstatResolver()
    except IndexError:
        input("Done!, press enter to continue ...")