#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auther: 2020, Mayed Alm
# NstatLogger: netstat logger of all TCP/IP and partially UDP communication from a host
# version: 1.8

import os
import sys
import csv
import time
import socket
import psutil
import argparse
import tempfile
import threading
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM


class NstatLogger:

    banner = '''
    _   __     __        __  __
   / | / /____/ /_____ _/ /_/ /   ____  ____ _____ ____  _____
  /  |/ / ___/ __/ __ `/ __/ /   / __ \/ __ `/ __ `/ _ \/ ___/
 / /|  (__  ) /_/ /_/ / /_/ /___/ /_/ / /_/ / /_/ /  __/ /
/_/ |_/____/\__/\__,_/\__/_____/\____/\__, /\__, /\___/_/
                                     /____//____/ v1.8    ©Mayed.alm

            '''

    def __init__(self):
        self.start = 'Started: ' + \
            time.ctime()[:19] # print the start time #print the start time
        if os.name == 'nt':
            self.tempdir = tempfile.gettempdir() + '\\'
        elif os.name == 'posix':
            self.tempdir = tempfile.gettempdir() + '/'
        self.filename = 'NstatLogger-' + \
            self.start[20:28].replace(':', '-') + '.log'  # file name with time
        self.tempfile = self.tempdir + self.filename
        self.mutex = threading.Lock()  # Mutex to control threads

    def cmd_args(self):
        print(NstatLogger.banner)
        parser = argparse.ArgumentParser(
            prog='NstatLogger',
            description=' [+] Log netstat like TCP/IP and UDP connections from host',
            epilog='[+] Example: NstatLogger -i 2 -t 3600 (will run NstatLogger for one hour, with 2 seconds interval/refresh)')
        parser.add_argument(
            '-t', '--timer', type=int, default=99**10, help='Set timer in seconds\
        of when to stop capturing, default will run until user termination (ctrl+c)')
        parser.add_argument(
            '-i',
            '--interval',
            type=int,
            default=3,
            help='Set capturing interval\
        in seconds, default is 3')
        self.args = parser.parse_args()
        self.interval = self.args.interval
        self.timer = self.args.timer
        return parser.parse_args()

    def timer_func(self):  # function to control execution time
        self.current_time = 0
        self.time_to_stop = self.current_time + self.timer
        while self.current_time <= self.time_to_stop:
            self.current_time += 1
            time.sleep(1)
            print(
                'Running (seconds): {:d}\r'.format(
                    self.current_time), end='')
            if self.current_time == self.time_to_stop:
                # releasing the lock for the threading to allow application to
                # continue execution
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
        self.templ = '%-5s %-5s %-5s %-5s %-5s %-5s %-5s %-5s %s'  # String formatting
        self.proc_names = {}
        self.proc_cmd = {}
        self.proc_time = {}
        self.running_stat = {}

        def capture_action():
            print(
                self.start +
                '\nPress Ctrl+c to properly stop of the tool!\nDON\'T OPEN THE CSV FILE WHILE THE TOOL IS RUNNING!')
            with open(self.tempfile, 'w') as f:
                f.write(
                    self.start +
                    '\n' +
                    self.templ %
                    ('Proto|',
                     'Local Address|',
                     'Remote Address|',
                     'Status|',
                     'PID|',
                     'Program Name|',
                     'Run Status|',
                     'Time Started|',
                     'Command Line|\n'))
            while self.current_time <= self.time_to_stop:
                for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
                    # assign key as pid and value as process name
                    self.proc_names[p.info['pid']] = p.info['name']
                    self.proc_cmd[p.info['pid']] = p.info['cmdline']
                    # running/stopped status
                    try:
                        self.running_stat[p.info['pid']] = str(
                        p).split(',')[2][8:].replace(')', '').replace("'","")
                    except IndexError:
                        self.running_stat[p.info['pid']] = '?'                    
                    #trying to get the process start time, if not put '?'
                    try:
                        self.proc_time[p.info['pid']] = str(
                        p).split(',')[3][9:].replace(')', '').replace(" ","_")
                    except IndexError:
                        self.proc_time[p.info['pid']] = '?'
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
                        if c.laddr.ip not in [
                                '0.0.0.0', '::', '127.0.0.1', '::1']:  # ignor localhost ip addresses
                            if not c.laddr.ip.startswith('fe80') and not c.laddr.ip.startswith(
                                    '169.254.'):  # ignore local-link address
                                laddr = '%s:%s' % (c.laddr)
                                self.raddr = ''
                                if c.raddr:
                                    self.raddr = '%s:%s' % (c.raddr)
                                with open(self.tempfile, 'a+') as f:
                                    f.writelines((self.templ %
                                                  (self.proto_map[(c.family, c.type)] +
                                                   '|', laddr +
                                                   '|', self.raddr +
                                                   '|', c.status +
                                                   '|', str(c.pid) +
                                                      '|' or self.AD +
                                                      '|', self.proc_names.get(c.pid, '?') +
                                                      '|', self.running_stat.get(c.pid, '?') +
                                                      '|', self.proc_time.get(c.pid, '?') +
                                                      '|', self.proc_cmd.get(c.pid, '?')) +
                                                   '\n'))
                                self.uniq(self.tempfile)
                time.sleep(self.interval)
                if self.current_time == self.time_to_stop:
                    self.mutex.acquire()  # locking (waiting) for the other thread to terminate
                    break
                else:
                    continue

        def main_threads():
            if self.interval and self.timer:
                th1 = threading.Thread(target=self.timer_func)
                th2 = threading.Thread(target=capture_action)
                th1.daemon = True
                th2.daemon = True
                self.mutex.acquire()
                th1.start()
                th2.start()
                while self.current_time <= self.time_to_stop:
                    time.sleep(self.interval)
                    if self.current_time == self.time_to_stop:
                        th1.join()  # wait until t1 terminates (make sure its finished)
                        th2.join()  # wait until t2 terminates (make sure its finished)
                        self.end()

        main_threads()

    def uniq(self, file_to_clean):  # write only uniq lines to output file
        lines_seen = set()  # holds lines already seen
        with open(self.filename, 'w') as outfile:
            for line in open(file_to_clean, 'r'):
                if line not in lines_seen:  # not a duplicate
                    outfile.write(line)
                    lines_seen.add(line)
        with open(self.filename, 'r') as txt_file:  # make csv file from the txt file
            stripped = (line.replace(' ', '') for line in txt_file) #remove empty spaces
            lines = (line.split("|") for line in stripped if line) #split words with | for making a csv file
            next(lines) #skip first line/row of start time
            clean_csv_List = [] #clean csv rows so that NstatAnalyzer understands it
            for line in lines:
                line[-1] = line[-1][:-1]
                clean_csv_List.append(line)
            with open(self.filename[:-3] + 'csv', 'w', newline='\n') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerows(clean_csv_List)

    def end(self):
        end_txt = ('Ended: ' + time.ctime()[:19])
        with open(self.filename, 'a') as txt_file_end:
            txt_file_end.write(end_txt)
        os.remove(self.tempfile)  # remove the non-uniq log file
        sys.exit(end_txt)


if __name__ == '__main__':
    try:
        n = NstatLogger()
        n.cmd_args()
        n.capture()
    except KeyboardInterrupt:
        n.end()
