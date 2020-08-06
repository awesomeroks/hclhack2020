import dpkt
import glob
import os
import sys
import pickle
import socket
import pandas as pd

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
            }

    if counter%50000 == 0:
        print('Reading Packet Number',counter)
    counter += 1
valuesDict = {}
def readFile(filePath):
    global fileName, label, valuesDict, tempFile
    resetParams()
    pcapFile = open(filePath, 'rb')
    pcap = dpkt.pcap.Reader(pcapFile)

    for ts, buf in pcap:
        extractFeatures(ts, buf)
    pcapFile.close()

    for key in frequencyDict.keys():
        time = frequencyDict[key]['prevTimeStamp'] - frequencyDict[key]['startTime']
        if time == 0:
            time = 1
        packetSize = (frequencyDict[key]['packetSizeFwd']*frequencyDict[key]['numberPacketsIn'] + frequencyDict[key]['packetSizeBwd']*frequencyDict[key]['numberPacketsOut'])/(frequencyDict[key]['numberPacketsIn'] + frequencyDict[key]['numberPacketsOut'])

        toWrite = '0,' + fileName +',' + str(key) +',' +  str(frequencyDict[key]['numberPacketsIn']) + ',' + str(frequencyDict[key]['numberPacketsOut']) + ',' +  str(packetSize) + ',' + str(frequencyDict[key]['protocol']) +',' + str(frequencyDict[key]['avgTimeInterval'] ) +',' + str(time )+',' + str(frequencyDict[key]['numberPacketsIn']/time )  + '\n'
        tempFile.write(toWrite)

tempFile = open('temp.csv','w')
tempFile.write('label, filename, nodePair, NumberPacketsIn, NumberPacketsOut, packetSize, protocol, avgTimeInterval, totalFlowTime, bwdps\n')
def startExec(path):
    global startTime, counter, ipDdos, udpDdos, icmpDdos, tcpDdos, prevTime,avgRequestInterval,frequencyDict, nFiles, fileName, label
    if os.path.isfile(path):
        fileName = os.path.basename(path).split('.')[0] 
        readFile(path)


if __name__ == "__main__": 
    inputArg = sys.argv[1]
    startExec(inputArg)
    tempFile.close()
    dataset = pd.read_csv('temp.csv')
    X = dataset.iloc[:, [3,4,5,6,7,8,9]].values
    y_testLabel = dataset.iloc[:, 2].values

    imputer = pickle.load(open('imputer.sav', 'rb'))
    X = imputer.transform(X)
    sc = pickle.load(open('scaler.sav', 'rb'))
    X = sc.transform(X)
    classifier = pickle.load(open('classifier.sav', 'rb'))
    y = classifier.predict(X)
    print(len(y))
    maliciousIps = y_testLabel[y>0.5]
    print(len(maliciousIps))
    f = open('output.csv','w')
    f.write('src,dst,output\n')
    for label in maliciousIps:
        splitIp = label.split(';')
        src = splitIp[0]
        dst = splitIp[1]
        f.write(src + ',' + dst +',MALICIOUS\n')
    f.close()