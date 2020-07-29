

f = open('Mixed_Data.csv')
lines =  f.readlines()
newLines = []
for line in lines:
    cells = line.split(',')
    tempLine = []
    for cell in cells:
        if cell.strip()[0:2] == '0x':
            cell = str(int(cell, 16))
        tempLine.append(cell.strip())
    newLines.append(tempLine)
fileNew = open('MixedData.csv', 'w')
for line in newLines:
    for cell in line:
        fileNew.write(cell + ', ')
    fileNew.write('\n')