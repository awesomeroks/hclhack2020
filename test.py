import glob

from collections import OrderedDict
import string
benign = 0
malignant = 0
total = 0
writeFile = open("Temp.txt", 'w')
peSectionsDict = OrderedDict()
optionalHeaderDict = OrderedDict()


class BytesIntEncoder:
#LIFTED FROM SACKOVERFLOW
    def __init__(self, chars: bytes = (string.ascii_letters + string.digits).encode()):
        num_chars = len(chars)
        translation = ''.join(chr(i) for i in range(1, num_chars + 1)).encode()
        self._translation_table = bytes.maketrans(chars, translation)
        self._reverse_translation_table = bytes.maketrans(translation, chars)
        self._num_bits_per_char = (num_chars + 1).bit_length()

    def encode(self, chars: bytes) -> int:
        num_bits_per_char = self._num_bits_per_char
        output, bit_idx = 0, 0
        for chr_idx in chars.translate(self._translation_table):
            output |= (chr_idx << bit_idx)
            bit_idx += num_bits_per_char
        return output

    def decode(self, i: int) -> bytes:
        maxint = (2 ** self._num_bits_per_char) - 1
        output = bytes(((i >> offset) & maxint) for offset in range(0, i.bit_length(), self._num_bits_per_char))
        return output.translate(self._reverse_translation_table)


encoder = BytesIntEncoder()
def executeStuff():
    global total, sectionCounter, peSectionsDict, hashName
    total += 1
    print(total)
    f = open(filepath + '/Structure_Info.txt', 'r', errors='replace')
    hashName = filepath.split('/')[-1].split('\\')[-1]
    fileText = f.read()
    peFeatures = fileText.split('----------PE Sections----------')
    peFeatures = peFeatures[1].split('----------Directories----------')[0]
    peSectionsTexts = peFeatures.split('[IMAGE_SECTION_HEADER]')
    peSectionsTexts.pop(0)

    for section in peSectionsTexts:
        tempDict = OrderedDict()
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
            line = []
            for element in templine:
                if(element not in [' ', '']):
                    line.append(element)
            lines.append(line)
        for line in lines:
            if(line[0][0:2] == '0x'):
                line.pop(0)
                line.pop(0)
                tempDict[line[0][:-1]] = line[-1]

        tempDict['Name'] = encoder.encode(tempDict['Name'].encode())
        peSectionsDict[sectionCounter] = tempDict
    writeFile.write(str(peSectionsDict) + '\n')

    optionalHeader = fileText.split('----------OPTIONAL_HEADER----------')
    optionalHeader = optionalHeader[1].split(
        '----------PE Sections----------')[0]
    optionalHeader = optionalHeader.split('\n')
    optionalHeader.pop(0)
    optionalHeader.pop(0)
    optionalHeader.pop(0)
    for line in optionalHeader:
        templine = line.split(' ')
        line = []
        for i in range(len(templine)):
            if templine[i] not in [' ', '']:
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
    # checkMalware()

    finalOut.write(hashName + ', ')
    for item in optionalHeaderDict:
        if str(optionalHeaderDict[item])[0:2] == '0x':
            finalOut.write(str(int(optionalHeaderDict[item], 16)) + ', ')
        else:
            finalOut.write(str(optionalHeaderDict[item]) + ', ')
    finalOut.write(', ')
    for item in peSectionsDict:
        for element in peSectionsDict[item]:
            if str(peSectionsDict[item][element])[0:2] == '0x':
                finalOut.write(
                    str(int(peSectionsDict[item][element], 16)) + ', ')
            else:
                finalOut.write(str(peSectionsDict[item][element]) + ', ')
        finalOut.write(', ')
    finalOut.write('\n')
    peSectionsDict = OrderedDict()

    f.close()


output = open('OP.csv', 'w')
sectionCounter = 0
finalOut = open('Backdoor.csv', 'w')
for filepath in glob.iglob('Static_Analysis_Data/Malware/Backdoor/*'):
    try:
        executeStuff()
    except:
        continue
