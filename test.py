import glob
import codecs


benign = 0
malignant = 0
total = 0
writeFile = open("Temp.txt",'w')
peSectionsDict = {}
optionalHeaderDict = {}

def sectionNameIsMalignant(name):
    return name not in ['.adata', '.text', '.data', '.rsrc', '.shared', '.page', '.init','.winzip','.bss', '.edata', '.idata', '.pdata', '.debug']

def checkMalware():
    global malignant
    malwareScore = 0
    if int(optionalHeaderDict["SizeOfInitializedData"],16) == 0:
        malwareScore += 1
    for item in peSectionsDict:
        if sectionNameIsMalignant(peSectionsDict[item]['Name']):
            malwareScore += 1
        elif (int(peSectionsDict[item]["Characteristics"],16) == 0 and int(optionalHeaderDict["SizeOfInitializedData"],16) == 0 and int(optionalHeaderDict["CheckSum"],16) == 0):
            malwareScore += 1
    # print(malwareScore)
    if malwareScore > 0:
        malignant += 1
    print(malignant/total)
    output.write( str(malwareScore) +  ', ' + hashName +'\n')

output = open('OP.csv', 'w')
sectionCounter = 0
for filepath in glob.iglob('Static_Analysis_Data/Benign/*'):
    try:
        total += 1
        
        f = open(filepath + '/Structure_Info.txt', 'r', errors='replace')
        hashName = filepath.split('/')[-1].split('\\')[-1]
        fileText = f.read()
        peFeatures = fileText.split('----------PE Sections----------')
        peFeatures = peFeatures[1].split('----------Directories----------')[0]
        peSectionsTexts = peFeatures.split('[IMAGE_SECTION_HEADER]')
        peSectionsTexts.pop(0)
        tempDict = {}
        for section in peSectionsTexts:
            sectionCounter += 1
            # peSections.append( Section(section, hashName))
            templines = section.split('\n')
            lines = []
            for line in templines:
                if line != '':
                    lines.append(line)
            templines = lines
            lines = []
            for line in templines:
                templine = line.split(' ')
                line =  []
                for element in templine:
                    if(element not in [' ', '']):
                        line.append(element)
                lines.append(line)
            for line in lines:
                if(line[0][0:2] == '0x'):
                    line.pop(0)
                    line.pop(0)
                    tempDict[line[0][:-1]] = line[-1]
            peSectionsDict[sectionCounter] = tempDict
        writeFile.write(str(peSectionsDict) + '\n')



        optionalHeader = fileText.split('----------OPTIONAL_HEADER----------')
        optionalHeader = optionalHeader[1].split('----------PE Sections----------')[0]
        optionalHeader = optionalHeader.split('\n')
        optionalHeader.pop(0)
        optionalHeader.pop(0)
        optionalHeader.pop(0)
        for line in optionalHeader:
            templine = line.split(' ')
            line = []
            for i in range(len(templine)):
                if templine[i] not in [ ' ', '']:
                    line.append(templine[i]) 
            if len(line) < 2 or line[0][0:3] == 'Dll':
                continue
            
            line.pop(0)
            line.pop(0)
            line = ''.join(line)
            splitLine = line.split(':')
            if len(line) < 2:
                continue
            optionalHeaderDict[splitLine[0]] = splitLine[1]
        writeFile.write(str(optionalHeaderDict) + '\n')
        sectionCounter = 0

        checkMalware()
        f.close()
    except:
        
        continue
        

    
    