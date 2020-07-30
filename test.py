import glob

from collections import OrderedDict
import string
benign = 0
malignant = 0
total = 0
writeFile = open("Temp.txt", 'w')
optionalHeaderDict = OrderedDict()
peSectionsTexts = ''

fileText = ''
def encode(string):
    sum = 0
    for char in string:
        sum += (ord(str(char))) 
    return sum

def getPEHeaders():
    global peSectionsTexts, fileText
    toRemove = []
    peFeatures = fileText.split('----------PE Sections----------')
    peFeatures = peFeatures[1].split('----------Directories----------')[0]
    peSectionsTexts = peFeatures.split('[IMAGE_SECTION_HEADER]')
    for i in range(len(peSectionsTexts)):
        peSectionsTexts[i] = peSectionsTexts[i].strip()
        if peSectionsTexts[i] in [' ','']:
            toRemove.append(i)
    for element in toRemove:
        peSectionsTexts.pop(element)
    toRemove = []
    for i in range(len(peSectionsTexts)):
        peSectionsTexts[i] = peSectionsTexts[i].split('\n')
        for j in range(len(peSectionsTexts[i])):
            peSectionsTexts[i][j] = peSectionsTexts[i][j].split(':')
            # if len(peSectionsTexts[i][j]) == 4 and peSectionsTexts[i][j][0] not in ['Flags:', 'Entropy:']:
            #     peSectionsTexts[i][j].pop(0)
            #     peSectionsTexts[i][j].pop(0)
            try:
                peSectionsTexts[i][j][-1] = str(int(peSectionsTexts[i][j][-1] ,16))
            except ValueError:
                peSectionsTexts[i][j][-1] = str(encode(peSectionsTexts[i][j][-1]))
            # peSectionsTexts[i][j][0] = peSectionsTexts[i][j][0].split(':')[0]
        peSectionsTexts[i].pop(-1)
        peSectionsTexts[i].pop(-1)
        peSectionsTexts[i].pop(-1)
        peSectionsTexts[i].pop(-1)
        # peSectionsTexts[i][-1].pop(-1)
        # peSectionsTexts[i][-1].pop(-1)
        peSectionsTexts[i].pop(-2)

def getPEFileHeader():
    global peFileTexts, fileText
    toRemove = []
    peFileFeatures = fileText.split('----------FILE_HEADER----------')
    peFileFeatures = peFileFeatures[1].split('----------OPTIONAL_HEADER----------')[0]
    peFileTexts = peFileFeatures.split('[IMAGE_FILE_HEADER]')
    for i in range(len(peFileTexts)):
        peFileTexts[i] = peFileTexts[i].strip()
        if peFileTexts[i] in [' ','']:
            toRemove.append(i)
    for element in toRemove:
        peFileTexts.pop(element)
    toRemove = []
    for i in range(len(peFileTexts)):
        peFileTexts[i] = peFileTexts[i].split('\n')
        for j in range(len(peFileTexts[i])):
            peFileTexts[i][j] = peFileTexts[i][j].split()
            if len(peFileTexts[i][j]) == 4 and peFileTexts[i][j][0] not in ['Flags:', 'Entropy:']:
                peFileTexts[i][j].pop(0)
                peFileTexts[i][j].pop(0)
                try:
                    peFileTexts[i][j][-1] = str(int(peFileTexts[i][j][-1] ,16))
                except ValueError:
                    peFileTexts[i][j][-1] = str(encode(peFileTexts[i][j][-1]))
            peFileTexts[i][j][0] = peFileTexts[i][j][0].split(':')[0]
        peFileTexts[i].pop(-1)
        peFileTexts[i].pop(2)

def getOptionalHeader():
    global optionalFileText, fileText
    toRemove = []
    optionalFileFeatures = fileText.split('----------OPTIONAL_HEADER----------')
    optionalFileFeatures = optionalFileFeatures[1].split('----------PE Sections----------')[0]
    optionalFileText = optionalFileFeatures.split('[IMAGE_OPTIONAL_HEADER]')
    for i in range(len(optionalFileText)):
        optionalFileText[i] = optionalFileText[i].strip()
        if optionalFileText[i] in [' ','']:
            toRemove.append(i)
    for element in toRemove:
        optionalFileText.pop(element)
    toRemove = []
    for i in range(len(optionalFileText)):
        optionalFileText[i] = optionalFileText[i].split('\n')
        for j in range(len(optionalFileText[i])):
            optionalFileText[i][j] = optionalFileText[i][j].split()
            if len(optionalFileText[i][j]) == 4 and optionalFileText[i][j][0] not in ['Flags:', 'Entropy:']:
                optionalFileText[i][j].pop(0)
                optionalFileText[i][j].pop(0)
                try:
                    optionalFileText[i][j][-1] = str(int(optionalFileText[i][j][-1] ,16))
                except ValueError:
                    optionalFileText[i][j][-1] = str(encode(optionalFileText[i][j][-1]))
            optionalFileText[i][j][0] = optionalFileText[i][j][0].split(':')[0]
        optionalFileText[i].pop(-1)


def executeStuff():
    global total, sectionCounter, peSectionsDict, hashName, fileText, peFileTexts, finalOut
    total += 1
    if total%100 == 0:
        print(total)
    f = open(filepath + '/Structure_Info.txt', 'r', errors='replace')
    hashName = filepath.split('/')[-1].split('\\')[-1]
    fileText = f.read()
    
    getPEHeaders()
    getPEFileHeader()
    getOptionalHeader()
    # for i in range(len(peFileTexts)):
    finalOut.write(hashName + ',')
    for section in peFileTexts:
        for item in section:
            finalOut.write(item[-1] + ',')
    finalOut.write(',')
    for section in optionalFileText:
        for item in section:
            finalOut.write(item[-1] + ',')
    for section in peSectionsTexts:
        for item in section:
            finalOut.write(item[-1] + ',')
        finalOut.write(',')
    
        
    finalOut.write('\n')
    f.close()


malwareType = 'Benign'
path = 'Static_Analysis_Data/' + malwareType  + '/*'
filesWithError = open('FilesWithError'+malwareType, 'w')
finalOut = open(malwareType + '.csv', 'w')
print('RUNNING ', 'BENIGN', path)
for filepath in glob.iglob(path):
    try:
        executeStuff()
    except:
        filesWithError.write(filepath + '\n')
    continue
filesWithError.close()
finalOut.close()
types = ['Virus','Trojan','TrojanDownloader', 'TrojanDropper', 'Worm', 'Backdoor']
for malwaretype in types:
    path = 'Static_Analysis_Data/' + 'Malware/' + malwaretype +'/*'
    total = 0
    print('RUNNING ', malwaretype, path)
    filesWithError = open('FilesWithError'+malwaretype, 'w')
    finalOut = open(malwaretype + '.csv', 'w')
    for filepath in glob.iglob(path):
        try:
            executeStuff()
        except:
            filesWithError.write(filepath + '\n')
            print("ERROR")
        continue
    filesWithError.close()
    finalOut.close()
