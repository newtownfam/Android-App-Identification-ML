'''
CS AdvNetworks
Phase 2
Peter Christakos
Andrew Morrison

'''

import pyshark
from classifyFlows import main, Flow, Burst
import csv

burstList = []

def csv_writer(foldername, app, file):

	for i in range(1,51):
		filenum = str(i)
		if i < 10:
			filenum = "0" + str(i)

		try:
			burstList.extend(main(["/opt/" + foldername + "/" + filenum + ".pcap"]))
		except:
			print("error occured")
		
	with open('/opt/' + file + '.csv', mode='w') as pcapfile:
		pcap_writer = csv.writer(pcapfile, delimiter = ',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		for burst in burstList:
			for flow in burst.flows:
				row = [app]

				#timestamp
				timediff = (flow.endTime - flow.startTime)
				row.append(str(timediff.seconds*100000 + timediff.microseconds)) 

				# total packets
				row.append(str(flow.pktSent + flow.pktRecv))

				# ethtype
				row.append(flow.ethtype)

				# ttl
				row.append(str(flow.ttl))

				# flags
				row.append(str(flow.flags))

				# all packet lengths
				for packet in flow.packetLengths:
					row.append(str(packet))

				

			pcap_writer.writerow(row)

csv_writer("wikipcap", "Wikipedia", 'wikipedia')
#csv_writer("fruitninjapcap", "Fruit Ninja", 'fruitninja')
#csv_writer("weatherpcap", "Weather Channel", 'weather')
#csv_writer("newspcap", "Google News", 'news')
