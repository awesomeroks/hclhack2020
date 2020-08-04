import os
# Function to rename multiple files
def main():
   i = 0
   path="I:/datasettemp/PS2/Ddos_Detection_Dataset/Ddos_Attack_data/"
   for filename in os.listdir(path):
      my_dest = 'ATTACK' + str(i).zfill(4) + ".pcap"
      my_source =path + filename
      my_dest =path + my_dest
      os.rename(my_source, my_dest)
      i += 1
# Driver Code
if __name__ == '__main__':
   # Calling main() function
   main()