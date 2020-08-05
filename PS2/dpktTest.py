import dpkt
import glob
import os
import socket
import multiprocessing 
import winsound
f = open('benigndataset.csv','w')
f1 = open('attackDataset.csv','w')
frequencyDict = {}
nFiles = 0
fileName = ''
def resetParams():
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval, frequencyDict
    counter = 0
    startTime = 0
    prevTime = 0
    ipDdos = 0
    udpDdos = 0
    icmpDdos = 0
    frequencyDict = {}
    avgRequestInterval = 0
    tcpDdos = 0

def executeUpdates(key2, protocol, packetSize, timestamp, inside ):
    length = frequencyDict[key2]['numberPacketsIn'] + frequencyDict[key2]['numberPacketsOut']
    

    frequencyDict[key2]['protocol'] = (frequencyDict[key2]['protocol']*length + protocol)/(length + 1) # Protocol average
    
    frequencyDict[key2]['avgTimeInterval'] =  (frequencyDict[key2]['avgTimeInterval']*length + (timestamp - frequencyDict[key2]['prevTimeStamp']))/(length + 1) #avgTimeInterval
    frequencyDict[key2]['prevTimeStamp'] = timestamp
    if inside:
        frequencyDict[key2]['packetSizeFwd'] = ( frequencyDict[key2]['packetSizeFwd'] *length + float(packetSize) )/(length + 1) #packetSize
        frequencyDict[key2]['numberPacketsIn'] += 1 #increment length
    else:
        frequencyDict[key2]['packetSizeBwd'] = ( frequencyDict[key2]['packetSizeBwd'] *length + float(packetSize) )/(length + 1) #packetSize
        frequencyDict[key2]['numberPacketsOut'] += 1 #increment length

def extractFeatures(timestamp, buf):
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval,frequencyDict
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != 2048:
            return
        ip = eth.data
        protocol = ip.p
        dst = socket.inet_ntoa(ip.dst)
        src = socket.inet_ntoa(ip.src)
        packetSize = ip.len
        key1= src + ';' + dst
        key2 = dst + ';' + src
    except Exception as exc:
        print("Exception: {}".format(exc))
        return
    if key1 in frequencyDict.keys():
        executeUpdates(key1, protocol, packetSize, timestamp, True)
    elif key2 in frequencyDict.keys():
        executeUpdates(key2, protocol, packetSize, timestamp, False)
    else:
        frequencyDict[key1] = {
            'numberPacketsIn':1,
            'numberPacketsOut':0,
            'packetSizeFwd':float(packetSize),
            'packetSizeBwd':float(packetSize),
            'protocol':protocol,
            'avgTimeInterval':0,
            'prevTimeStamp':timestamp,
            'startTime' : timestamp
            } #NumberPacketsIn, NumberPacketsOut, Payload Length,  protocol, avgTimeInterval, previousTime
    # if counter == 0:
    #     prevTime = float(timestamp)
    #     counter += 1
    #     print(prevTime)
    #     return
    # startTime = float(timestamp)
    # avgRequestInterval = (avgRequestInterval*counter + startTime - prevTime)/(counter + 1)
    # prevTime = startTime
    if counter%50000 == 0:
        print('FIle number:', nFiles,counter)
    counter += 1

def readFile(filePath, fileToWrite):
    global fileName, label
    resetParams()
    pcapFile = open(filePath, 'rb')
    pcap = dpkt.pcap.Reader(pcapFile)


    for ts, buf in pcap:
        extractFeatures(ts, buf)
    pcapFile.close()

    # x = sorted(((v,k) for k,v in frequencyDict.items()))
    # print(x[-1])
    # src = x[-1][1].split(';')[0]
    # dst = x[-1][1].split(';')[1]
    # src = src.replace('.','')
    # dst = dst.replace('.','')
    # maxPacketsIn = int(x[-1][0][0])
    # maxPacketsOut = int(x[-1][0][1])
    # packetSize = x[-1][0][2]
    # ratioPackets = maxPacketsIn/maxPacketsOut
    #NumberPacketsIn, NumberPacketsOut, Payload Length,  protocol, avgTimeInterval, previousTime
    print(len(frequencyDict))
    for key in frequencyDict.keys():
        time = frequencyDict[key]['prevTimeStamp'] - frequencyDict[key]['startTime']
        if time == 0:
            time = 1
        packetSize = (frequencyDict[key]['packetSizeFwd']*frequencyDict[key]['numberPacketsIn'] + frequencyDict[key]['packetSizeBwd']*frequencyDict[key]['numberPacketsOut'])/(frequencyDict[key]['numberPacketsIn'] + frequencyDict[key]['numberPacketsOut'])
        toWrite = label + ',' + fileName +',' + str(key) +',' +  str(frequencyDict[key]['numberPacketsIn']) + ',' + str(frequencyDict[key]['numberPacketsOut']) + ',' +  str(packetSize) + ',' + str(frequencyDict[key]['protocol']) +',' + str(frequencyDict[key]['avgTimeInterval'] ) +',' + str(time )+',' + str(frequencyDict[key]['numberPacketsIn']/time )  + '\n'
        # print(toWrite)
        fileToWrite.write(toWrite)
    # fileToWrite.write(str(round(1/avgRequestInterval, 2))+','+str(maxPacketsIn)  +','+str(maxPacketsOut)+','+str(ratioPackets)+',' + str(packetSize) +',' + str(src) +',' + str(dst) + '\n')

f.write('label, filename, nodePair, NumberPacketsIn, NumberPacketsOut, Payload Length, protocol, avgTimeInterval, totalFlowTime, bwdps\n')
f1.write('label, filename, nodePair,  NumberPacketsIn, NumberPacketsOut, Payload Length, protocol, avgTimeInterval, totalFlowTime, bwdps\n')
def benignExec():
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval,frequencyDict, nFiles, fileName, label
    label = '0'
    benignPath = 'I:/datasettemp/PS2/Ddos_Detection_Dataset/Ddos_benign/*'
    for filepath in sorted(glob.iglob(benignPath)):
        nFiles += 1
        if os.path.isfile(filepath):
            print('BENIGN',nFiles, filepath)
            fileName = os.path.basename(filepath).split('.')[0] 

            readFile(filepath, f)
def attackExec():
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval,frequencyDict, nFiles, fileName, label
    label = '1'
    attackPath = 'I:/datasettemp/PS2/Ddos_Detection_Dataset/Ddos_Attack_data/*'
    for filepath in sorted(glob.iglob(attackPath)):
        nFiles += 1
        if os.path.isfile(filepath):
            print('ATTACK',nFiles, filepath)
            fileName = os.path.basename(filepath).split('.')[0] 
            
            readFile(filepath, f1)

if __name__ == "__main__": 
    # printing main program process id 
    print("ID of main process: {}".format(os.getpid())) 
  
    # creating processes 
    p1 = multiprocessing.Process(target=benignExec) 
    p2 = multiprocessing.Process(target=attackExec) 
  
    # starting processes 
    p1.start() 
    p2.start() 
  
    # process IDs 
    print("ID of process p1: {}".format(p1.pid)) 
    # print("ID of process p2: {}".format(p2.pid)) 
  
    # wait until processes are finished 
    p1.join() 
    p2.join() 
  
    # both processes finished 
    print("Both processes finished execution!") 
  
    # check if processes are alive 
    print("Process p1 is alive: {}".format(p1.is_alive())) 
    # print("Process p2 is alive: {}".format(p2.is_alive())) 