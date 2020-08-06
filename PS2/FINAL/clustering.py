import csv


with open('benigndatasetDS2.csv','r') as csv_file:
	f = open('clusteredBenignDS2New.csv','w')
	csv_reader = csv.reader(csv_file)
	csv_reader_list=[]
	for item in csv_reader:
		csv_reader_list.append(item)
	#print(csv_reader_list)
	# count=1
	a=1
	while(a<512031):
		numInSum=0
		numOutSum=0
		payLoadLenSum=0
		protocolSum=0
		timeIntervalSum=0
		totalFlowTime=0
		bwdps=0
		for line in csv_reader_list[a:a+101]:
			numInSum+=float(line[3])
			numOutSum+=float(line[4])
			payLoadLenSum+=float(line[5])
			protocolSum+=float(line[6])
			timeIntervalSum+=float(line[7])
			totalFlowTime+=float(line[8])
			bwdps+=float(line[9])

		f.write(str(numInSum/100)+','+str(numOutSum/100)+','+str(payLoadLenSum/100)+','+str(protocolSum/100)+','+str(timeIntervalSum/100)+','+str(totalFlowTime/100)+','+str(bwdps/100)+'\n')
		a=a+100
		
	




