#!usr/bin/python 
from __future__ import print_function
import os 
import sys 
import re
from uuid import getnode as get_mac
import time
import argparse
import subprocess
import socket
from tqdm import tqdm
from collections import defaultdict
import netifaces
from netaddr import EUI, mac_unix_expanded
from wireless import Wireless

def run_process(cmd, err=False):
	err_pipe = subprocess.STDOUT if err else open(os.devnull, 'w')
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_pipe)
	while True:
		retcode = p.poll()
		line = p.stdout.readline()
		yield line
		if retcode is not None:
			break


def getMyMac():
	try:
		wireless = Wireless()
		ifaces = wireless.interfaces()
		iface = ifaces[-1]
		mac = (netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr'])
		return mac
	except:
		print("Please manually select your interface using ifconfig or ipconfig using the -i flag")
		sys.exit(-1)


def collectDataWShark (packets, interface, sources):
	myIP = (socket.gethostbyname(socket.gethostname()))
	cmd = 'sudo tshark -i {} -c {} -e eth.src -e eth.dst -e ip.src -e ip.dst  -T fields'.format(interface, packets).split()
	sharkSources = {}
	try:
		bar_format = '{n_fmt}/{total_fmt} {bar} {remaining}'
		progress = tqdm(run_process(cmd), total=packets, bar_format=bar_format)
		for line in progress:
			data = line.split()
			if len(data) == 4:
				ip = data[2]
				mac = data[0]
			if ip and mac and ip[0:5] == myIP[0:5]:
					source = ("MAC Address : "+ mac +"    IPv4 Address : " +ip)
					if source not in sources:
						sources[source] = 1
					else:
						sources[source] += 1
					if source not in sharkSources:
						sharkSources[source] = 1
					else:
						sharkSources[source] += 1
			if len(data) == 4:
				ip = data[3]
				mac = data[1]
			if ip and mac and ip[0:5] == myIP[0:5]:
					source = ("MAC Address : "+ mac+"    IPv4 Address : " + ip)
					if source not in sources:
						sources[source] = 1
					else:
						sources[source] += 1
					if source not in sharkSources:
						sharkSources[source] = 1
					else:
						sharkSources[source] += 1

		if progress.n < progress.total:
			print('Sniffing finished early.')
	except subprocess.CalledProcessError:
		print('Error collecting packets.')
		raise
	except KeyboardInterrupt:
		pass
	return sharkSources


def collectDataNMAP(sources):
	myIP = (socket.gethostbyname(socket.gethostname()))
	ipRange = str(myIP) + '/24'
	fname = 'nmap.txt'
	cmd = 'sudo nmap {} -sn -v0 -oN {}'.format(ipRange, fname)
	#print (cmd)
	os.system(cmd)
	#run_process(cmd)

	#sources = {}
	count = 1
	line = ""
	first = True 
	nmapSources = {}
	with open(fname) as f:
		content = f.readlines()
		for curLine in content:
			if first:
				first = False
				continue
			if (count == 3):
				line += str(curLine)
				line = line.replace('\n',' ').lower()
				#print (line)
				m = re.search(r'[a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}', line)
				ip = re.search(r'[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}', line)
				if m and ip:
						source = ("MAC Address : ", m.group() ,"    IPv4 Address : " , ip.group())
						if source not in sources:
							sources[source] = 1
						else:
							sources[source] += 1
						if source not in nmapSources:
							nmapSources[source] = 1
						else:
							nmapSources[source] += 1
				line = ""
				count = 1
			else :
				count += 1
				line += str(curLine)
	#print (sources)
	return nmapSources


def collectDataTCP(packets, interface, sources):
	fname = "trace.txt"
	# clear file
	open('trace.txt', 'w').close()

	#sources = {}
	# doesn't work with I option (monitor mode)
	cmd = 'sudo tcpdump -i {} -len -c {} -s 0'.format(interface, packets).split()
	#print (cmd)
	tcpSources = {}
	try:
		bar_format = '{n_fmt}/{total_fmt} {bar} {remaining}'
		progress = tqdm(run_process(cmd), total=packets, bar_format=bar_format)
		for line in progress:
			line = line.decode()
			m = re.search(r'[a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}', line)
			ip = re.search(r'[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}', line)
			if m and ip:
					source = ("MAC Address : ", m.group() ,"    IPv4 Address : " , ip.group())
					if source not in sources:
						sources[source] = 1
					else:
						sources[source] += 1
					if source not in tcpSources:
						tcpSources[source] = 1
					else:
						tcpSources[source] += 1

		if progress.n < progress.total:
			print('Sniffing finished early.')
	except subprocess.CalledProcessError:
		print('Error collecting packets.')
		raise
	except KeyboardInterrupt:
		pass
	return tcpSources

def printSources(sources):
	mac = getMyMac()
	myIP = (socket.gethostbyname(socket.gethostname()))
	for key in sources:
		if (key[1] != mac and key[3][0:5] == myIP[0:5]):
			print (key[0], key[1], key[2], key[3], "   Count: ", sources[key])

def cleanData(sources):
	mac = getMyMac()
	myIP = (socket.gethostbyname(socket.gethostname()))
	newSources = {}
	for key in sources:
		if (key[1] == 'N/A'):
			#print (key[0], key[1], key[2], key[3], "   Count: ", sources[key])
			for key2 in sources:
				currentMac = key2[1]
				currentIP = key2[3]
				if (currentMac != 'N/A' and currentIP == key[3]):
					sources[key2] += sources[key]

	for key in sources:
		if (key[1] != 'N/A'):
			newSources[key] = sources[key]

	#printSources(newSources)
	return newSources

def changeMac(sources, verbose): 

	high = 0
	high_key = ""
	mac = getMyMac()
	myIP = (socket.gethostbyname(socket.gethostname()))
	#output = os.system("ifconfig en0 | grep ether")
	
	#print ("Previous MAC address: " + mac + "  My IP:  " + myIP)
	for key in sources:
		if (key[1] != mac and key[3][0:5] == myIP[0:5]):
			if (verbose):
				print (key[0], key[1], key[2], key[3], "   Count: ", sources[key])
			if (sources[key] > high):
				high = sources[key]
				high_key = key

	if high_key != "":
		print ("-------------------Ideal MAC----------------------")
		print ("Ideal to change MAC to: " + high_key[1])
		print ("-------------------Change MAC---------------------")
		print ("Run command: sudo macattc -changeMAC [MAC Address]")
		print ("Replace [MAC Address] with the ideal MAC address or another of your choice.")
		print ("Remember, it may take over 30 seconds to reconnect after your MAC address is changed.")

	else :
		print ("No hosts found")
	return high_key
	



def main():

	parser = argparse.ArgumentParser(
		description='Find active users on the current wireless network.')
	parser.add_argument('-p', '--packets',
						default=100,
						type=int,
						help='How many packets to capture.')
	parser.add_argument('-i', '--interface',
						default='en0',
						type=str,
						help='Which wireless interface to use.')
	parser.add_argument('-v', '--verbose',
						action='store_true')
	parser.add_argument('-f', '--file',
						action='store_true',
						help='logs the trace.txt and nmap.txt')
	parser.add_argument('-changeMAC', '--mac',
						default=None,
						type=str,
						help='MAC addres to change to.')

	args = parser.parse_args()

	if (args.mac == None):
		myIP = (socket.gethostbyname(socket.gethostname()))
		mac = getMyMac()
		allSources = {}
		verbose = args.verbose
		print ("-------------------Previous data -----------------")
		print ("Previous MAC address: " + mac + "        My IP:  " + myIP)
		print ("-------------------TCP data collection------------")
		tcpSources = collectDataTCP(args.packets, args.interface, allSources)
		if (verbose):
			printSources(tcpSources)
		print ("Done")
		print ("-------------------NMAP data collection------------")
		nmapSources = collectDataNMAP(allSources)
		if (verbose):
			printSources(nmapSources)
		print ("Done")
		print ("-------------------Tshark data collection----------")
		sharkSources = collectDataWShark(args.packets, args.interface, allSources)
		if (verbose):
			printSources(sharkSources)
		print ("Done")
		print ("-------------------All Data results----------------")
		allSources = cleanData(allSources)
		high = changeMac(allSources, True)
		print ("---------------------------------------------------")
	else :
		m = ""
		m = re.search(r'[a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}', args.mac)
		if (m == ""):
			print ("Error on MAC input")
		else:
			platform = sys.platform
			wireless = Wireless()
			ifaces = wireless.interfaces()
			iface = ifaces[-1]
			if (platform == 'linux' or platform == 'linux2'):
				os.system("/etc/init.d/networking stop") 
				os.system("ifconfig " + iface + " hw ether " + args.mac) 
				os.system("/etc/init.d/networking start") 
			elif (platform == 'darwin'):
				os.system("sudo ifconfig en0 ether " + args.mac)
			elif (platform == 'win32'):
				print ("Not implemented")
			else:
				print ("Unknown Operating system")
			print ("Changing MAC to: " + args.mac)
			print ("Remember, it may take over 30 seconds to reconnect after your MAC address is changed.")
			if os.path.exists('trace.txt') and args.file:
				os.remove('trace.txt')
			if os.path.exists('nmap.txt') and args.file:
				os.remove('nmap.txt')

			