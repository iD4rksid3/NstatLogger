#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auther: 2019, Mayed Alm
# NstatLogger: netstat logger of all TCP/IP and UDP communication from a host
# version: 1.0

import os
import ssl
import sys
import time
import json
import socket
import psutil
import requests
import argparse
import threading
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
from requests.packages.urllib3.contrib import pyopenssl as reqs

class NstatLogger:
    
    banner = ''' 
    _   __     __        __  __                               
   / | / /____/ /_____ _/ /_/ /   ____  ____ _____ ____  _____
  /  |/ / ___/ __/ __ `/ __/ /   / __ \/ __ `/ __ `/ _ \/ ___/
 / /|  (__  ) /_/ /_/ / /_/ /___/ /_/ / /_/ / /_/ /  __/ /    
/_/ |_/____/\__/\__,_/\__/_____/\____/\__, /\__, /\___/_/     
                                     /____//____/ v1.0    ©Mayed.alm    
                                     
            '''
    
    def __init__(self):      
        self.start = 'Started: ' + time.ctime()[:19]+'\n'  #print the start time
        self.filename = 'NstatLogger-'+time.ctime()[11:19].replace(':','-')+'.log' #file name with time 
        self.mutex = threading.Lock() #Mutex to control threads
        
    def cmd_args(self):        
        print(NstatLogger.banner)
        parser = argparse.ArgumentParser(prog='NstatLogger',\
            description=' [+] Log netstat like TCP/IP and UDP connections from host',\
            epilog='[+] Example: NstatLogger -i 2 -t 3600 (will run NstatLogger for one hour, with 2 seconds interval/refresh)')
        parser.add_argument('-r', '--resolve', type=argparse.FileType('r'), help='Perform reverse IP lookup')
        parser.add_argument('-t', '--timer', type=int,default=99**10, help='Set timer in seconds\
        of when to stop capturing, default will run until user termination (ctrl+c)')
        parser.add_argument('-i', '--interval', type=int, default=3, help='Set capturing interval\
        in seconds, default is 3')
        self.args = parser.parse_args()
        self.interval = self.args.interval
        self.timer = self.args.timer
        return parser.parse_args()
    
    
    def timer_func(self):  #function to control execution time
        self.current_time =  0     
        self.time_to_stop = self.current_time + self.timer
        while self.current_time <= self.time_to_stop:   
            self.current_time += 1
            time.sleep(1)
            print('Running (seconds): {:d}\r'.format(self.current_time), end='')
            if self.current_time == self.time_to_stop:
                self.mutex.release()
                break
                
    
    
    def capture(self):
        self.AD = '-'
        AF_INET6 = getattr(socket, 'AF_INET6', object())
        self.proto_map = {
            (AF_INET, SOCK_STREAM): 'tcp',
            (AF_INET6, SOCK_STREAM): 'tcp6',
            (AF_INET, SOCK_DGRAM): 'udp',
            (AF_INET6, SOCK_DGRAM): 'udp6',
            }
        self.templ = '%-5s %-21s %-20s %-15s %-10s %-20s %-24s %s' #String formatting
        self.proc_names = {}
        self.proc_cmd = {}
        self.proc_time = {}
      
        
        def capture_action():
            print(self.start+'\nPress Ctrl+c to properly stop of the tool!')
            with open(self.filename, 'w') as f:
                f.write(self.start + '\n'+ self.templ % \
                    ('Proto', 'Local address', 'Remote address', 'Status',\
                     'PID', 'Program name', 'Time started', 'Command line') + '\n')            
            while self.current_time <= self.time_to_stop:
                for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
                    self.proc_names[p.info['pid']] = p.info['name'] #assign key as pid and value as name
                    self.proc_cmd[p.info['pid']] = p.info['cmdline']
                    self.proc_time[p.info['pid']] = str(p).split(',')[2][9:].replace(')','')
                for c in psutil.net_connections(kind='inet'):
                    if c.status == psutil.CONN_ESTABLISHED\
                       or c.status == psutil.CONN_SYN_SENT\
                       or c.status == psutil.CONN_SYN_RECV\
                       or c.status == psutil.CONN_FIN_WAIT1\
                       or c.status == psutil.CONN_FIN_WAIT2\
                       or c.status == psutil.CONN_TIME_WAIT\
                       or c.status == psutil.CONN_CLOSE\
                       or c.status == psutil.CONN_CLOSE_WAIT\
                       or c.status == psutil.CONN_LAST_ACK\
                       or c.status == psutil.CONN_CLOSING\
                       or c.status == psutil.CONN_NONE:
                        if c.laddr.ip not in  ['0.0.0.0','::','127.0.0.1', '::1']: #ignor localhost ip addresses
                            if not c.laddr.ip.startswith('fe80') and not c.laddr.ip.startswith('169.254.'): #ignore local-link address
                                laddr = '%s:%s' % (c.laddr)
                                self.raddr = ''
                                if c.raddr:
                                    self.raddr = '%s:%s' % (c.raddr)
                                with open(self.filename ,'a+') as f:
                                        f.writelines((self.templ % \
                                            (self.proto_map[(c.family, c.type)], laddr, self.raddr, \
                                                c.status, c.pid or self.AD, self.proc_names.get(c.pid, '?')[:22],\
                                                self.proc_time.get(c.pid, '?'), self.proc_cmd.get(c.pid, '?')), '\n'))
                                self.uniq(self.filename)
                time.sleep(self.interval)
                if self.current_time == self.time_to_stop:
                    self.mutex.acquire()
                    break
                else:
                    continue
        
                    
        def main_threads():
            if self.args.resolve:
                try:
                    self.reslove_func(self.args.resolve.name)
                except KeyboardInterrupt:
                    sys.exit('\nInterrupted!')
            elif self.interval and self.timer:
                th1 = threading.Thread(target = self.timer_func)
                th2 = threading.Thread(target = capture_action)
                th1.daemon = True
                th2.daemon = True
                self.mutex.acquire()
                th1.start() ; th2.start()
                while self.current_time <= self.time_to_stop:
                    time.sleep(self.interval)
                    if self.current_time == self.time_to_stop:
                        th1.join()
                        th2.join()
                        self.end()
                    
        main_threads()
           
        
    def uniq(self, file_to_clean): #write only uniq lines to output file      
        lines_seen = set() # holds lines already seen
        with open(file_to_clean[:20]+'-Uniq.log', 'w') as outfile:
            for line in open(file_to_clean, 'r'):
                if line not in lines_seen: # not a duplicate
                    outfile.write(line)
                    lines_seen.add(line)  
        
    
    def end(self):
        end = ('\n'+'Ended: ' + time.ctime()[:19])      
        with open(self.filename[:20]+'-Uniq.log', 'a') as a:
            a.write(end)
        os.remove(self.filename) #remove the non-uniq log file
        sys.exit(end)
                
        
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

        
    

def main():
    try:
        n = NstatLogger()
        n.cmd_args()
        n.capture()
    except KeyboardInterrupt:
        n.end()
    except IndexError:
        sys.exit('ERROR: Unable to read file, make sure it\'s an NstatLogger log file!')
if __name__=='__main__':
        main()
    
    
