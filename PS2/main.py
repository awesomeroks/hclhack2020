from scapy.all import *
import glob
import os
f = open('pktData.csv','w')

def writeInterval(packets):
    startTime = 0
    prevTime = 0
    avgRequestInterval = 0
    counter = 0
    for packet in packets:
        if counter == 0:
            prevTime = packet.time
            counter += 1
            continue
        startTime = packet.time
        avgRequestInterval = (avgRequestInterval*counter + startTime - prevTime)/(counter + 1)
        prevTime = startTime
        counter += 1

        if counter == 200:
            break
    f.write(str(round(avgRequestInterval,6))+','+str(round(avgRequestInterval,6))  +'\n')
    

# writeInterval(PcapReader('ddos.pcap'))
# writeInterval(PcapReader('1.pcap'))
attackPath = 'I:/datasettemp/PS2/Ddos_Detection_Dataset/*/*'
benignPath = 'I:/datasettemp/PS2/Ddos_Detection_Dataset/*/*/*'
paths = [attackPath, benignPath]
for path in paths:
    for filepath in sorted(glob.iglob(path)):
        print(filepath)
        if os.path.isfile(filepath):
            if path == attackPath:
                f.write('1,' + os.path.basename(filepath).split('.')[0] +',')
                writeInterval(PcapReader(filepath))
            else:
                f.write('0,' + os.path.basename(filepath).split('.')[0] +',')
                writeInterval(PcapReader(filepath))

