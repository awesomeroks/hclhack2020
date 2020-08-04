import pyshark
import glob
import os
f = open('pktData1.csv','w')
tsharkPath = 'I:/ProgramFiles/wireshark/WiresharkPortable/App/Wireshark/tshark.exe'


def resetParams():
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval
    counter = 0
    startTime = 0
    prevTime = 0
    ipDdos = 0
    udpDdos = 0
    icmpDdos = 0
    avgRequestInterval = 0
    tcpDdos = 0
def extractFeatures(packet):
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval
    prevTime = 0
    if packet.transport_layer == 'UDP':
        udpDdos += 1
    elif packet.transport_layer == 'TCP':
        tcpDdos += 1
    elif packet.transport_layer == 'ICMP':
        icmpDdos += 1
    elif packet.transport_layer == 'IP':
        ipDdos += 1
    if counter == 0:
        prevTime = float(packet.sniff_timestamp)
        counter += 1
        return
    startTime = float(packet.sniff_timestamp)
    avgRequestInterval = (avgRequestInterval*counter + startTime - prevTime)/(counter + 1)
    prevTime = startTime
    counter += 1
    if counter%5000 == 0:
        print(counter)
    

def readFile(filePath):
    packets = pyshark.FileCapture(filePath, tshark_path =tsharkPath)
    resetParams()
    packets.apply_on_packets(extractFeatures)
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
                readFile(filepath)
                
            else:
                print('BENIGN', filepath)
                f.write('0,' + os.path.basename(filepath).split('.')[0] +',')
                readFile(filepath)

