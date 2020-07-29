import glob



benign = 0
malignant = 0
total = 0
writeFile = open("Temp.txt",'w')
peSectionsDict = {}
optionalHeaderDict = {}
# class Section:
#     def __init__(self, sectionFileText, hashName):
#         lines = sectionFileText.split('\n')
#         lines.pop(0)
#         lines = [line.replace(' ', '') for line in lines]
#         self.Name = lines[0].split('Name:')[1]
#         self.Misc = lines[1].split('Misc:')[1]
#         self.Misc_PhysicalAddress = lines[2].split('Misc_PhysicalAddress:')[1]
#         self.Misc_VirtualSize = lines[3].split('Misc_VirtualSize:')[1]
#         self.VirtualAddress = lines[4].split('VirtualAddress:')[1]
#         self.SizeOfRawData = lines[5].split('SizeOfRawData:')[1]
#         self.PointerToRawData = lines[6].split('PointerToRawData:')[1]
#         self.PointerToRelocations = lines[7].split('PointerToRelocations:')[1]
#         self.PointerToLinenumbers = lines[8].split('PointerToLinenumbers:')[1]
#         self.NumberOfRelocations = lines[9].split('NumberOfRelocations:')[1]
#         self.NumberOfLinenumbers = lines[10].split('NumberOfLinenumbers:')[1]
#         self.Characteristics = lines[11].split('Characteristics:')[1]
#         self.flags = lines[12].split('Flags:')[1]
#         self.entropy = float(lines[13].split('Entropy:')[1].split('(')[0])
#         self.md5 = lines[14].split('MD5hash:')[1]
#         self.sha1 = lines[15].split('SHA-1hash:')[1]
#         self.sha256 = lines[16].split('SHA-256hash:')[1]
#         self.sha512 = lines[17].split('SHA-512hash:')[1]
#         print(self.Name)
#         writeFile.write(self.Characteristics)
#         writeFile.write('\n')
def checkMalware():
    if SizeOfInitializedData == 0:
        return True
    elif sectionName:
        return True
    elif (self.Characteristics == 0 and MajorImageVersion == 0 and CheckSum == 0):
        return True
    else:
        return False

sectionCounter = 0
for filepath in glob.iglob('Static_Analysis_Data/Benign/*'):
    total += 1
    f = open(filepath + '/Structure_Info.txt', 'r')
    hashName = filepath.split('/')[-1]
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
            print()
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
        if len(line) < 2:
            continue
        line.pop(0)
        line.pop(0)
        print(line)
        line = ''.join(line)
        splitLine = line.split(':')
        optionalHeaderDict[splitLine[0]] = splitLine[1]
    writeFile.write(str(optionalHeaderDict) + '\n')
    break