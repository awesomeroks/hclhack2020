from scapy.all import *
import glob
import os
f = open('pktData2.csv','w')

def writeInterval(packets):
    startTime = 0
    prevTime = 0
    avgRequestInterval = 0
    counter = 0
    ipDdos = 0
    udpDdos = 0
    icmpDdos = 0
    tcpDdos = 0
    for packet in packets:
        if UDP in packet:
            udpDdos+= 1
        if ICMP in packet:
            icmpDdos+= 1
        if TCP in packet:
            tcpDdos+= 1


        if counter == 0:
            prevTime = packet.time
            counter += 1
            continue
        startTime = packet.time
        avgRequestInterval = (avgRequestInterval*counter + startTime - prevTime)/(counter + 1)
        prevTime = startTime
        counter += 1
        if counter%5000 == 0:
            print(counter)
        # if counter == 100:
        #     break
    f.write(str(round(avgRequestInterval,6))+','+str(udpDdos)  +','+str(icmpDdos)+','+str(tcpDdos)+'\n')
    

# writeInterval(PcapReader('ddos.pcap'))
# writeInterval(PcapReader('1.pcap'))
# benignPath = 'I:/datasettemp/PS2/Ddos_Detection_Dataset/Ddos_benign/*'
attackPath = 'I:/datasettemp/PS2/Ddos_Detection_Dataset/Ddos_Attack_data/*'
paths = [attackPath]#, benignPath]
for path in paths:
    for filepath in sorted(glob.iglob(path)):
        
        if os.path.isfile(filepath):
            if path == attackPath:
                f.write('1,' + os.path.basename(filepath).split('.')[0] +',')
                print('ATTACK', filepath)
                writeInterval(PcapReader(filepath))
                
            else:
                print('BENIGN', filepath)
                f.write('0,' + os.path.basename(filepath).split('.')[0] +',')
                writeInterval(PcapReader(filepath))

