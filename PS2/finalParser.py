import os
from scapy.all import *
import glob


f = open('ddosCalls2.csv','w')
file_list = glob.glob('C:/Users/Gautam Vashishtha/Downloads/Ddos_Detection_Dataset/Ddos_Detection_Dataset/trial/[0-9][0-9][0-9]')
for file in file_list:
	print('file name is '+ file)
	packetsDdos = rdpcap(str(file))
	ipDdos = 0
	udpDdos = 0
	icmpDdos = 0
	tcpDdos = 0
	for packet in packetsDdos:
     	 # print(packet)
  		if 'UDP' in packet:
			udpDdos+= 1
  		if 'ICMP' in packet:
			icmpDdos+= 1
  		if 'TCP' in packet:
			tcpDdos+= 1
	f.write( str(ipDdos)+',' +str(udpDdos)+','+str(icmpDdos)+','+str(tcpDdos)+'\n')

    

