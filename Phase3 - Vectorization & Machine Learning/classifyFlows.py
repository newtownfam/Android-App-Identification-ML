'''
CS AdvNetworks
Phase 2
Peter Christakos
Andrew Morrison

'''

#import dpkt
import pyshark
import sys
import datetime

# create a burst
class Burst:
	def __init__(self, id, time, filenum):
		self.id = id
		self.time = time
		self.flows = []
		self.filenum = filenum

# create a flow
class Flow:
	def __init__(self, srcAddr, destAddr, srcPort, destPort, bytesTr, bytesRecv, pktSent, pktRecv, timeStamp, protocol):
		self.srcAddr = srcAddr
		self.destAddr = destAddr
		self.srcPort = srcPort
		self.destPort = destPort
		self.bytesTr = bytesTr
		self.bytesRecv = bytesRecv
		self.pktSent = pktSent
		self.pktRecv = pktRecv
		self.timeStamp = timeStamp
		self.protocol = protocol

def create_flow(pkt):
	# if sent, add to packets sent
	if '192.168.12' in pkt.ip.src:	
		flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, int(pkt.length), 0, 1, 0, pkt.sniff_time, pkt.transport_layer)
	# else, add to packets recv
	else:
		flow = Flow(pkt.ip.dst, pkt.ip.src, pkt[pkt.transport_layer].dstport, pkt[pkt.transport_layer].srcport, 0, int(pkt.length), 0, 1, pkt.sniff_time, pkt.transport_layer)
	return flow


def update_flows(pkt, flows):
	for flow in flows:
		if "192.168.12" not in pkt.ip.src:
			# incr recv
			if (flow.destAddr == pkt.ip.src) and (flow.destPort == pkt[pkt.transport_layer].srcport) and (flow.protocol == pkt.transport_layer):
				#update connection
				flow.bytesRecv += int(pkt.length)
				flow.pktRecv += 1
		elif "192.168.12" in pkt.ip.src:
			# incr tr
			if (flow.destAddr == pkt.ip.dst) and (flow.destPort == pkt[pkt.transport_layer].dstport) and (flow.protocol == pkt.transport_layer):
				#update connection
				flow.bytesTr += int(pkt.length)
				flow.pktSent += 1
	return flows

def print_bursts(burstList):
	for burst in burstList:
		print("File: " + str(burst.filenum) + ", Burst: " + str(burst.id))
		for flow in burst.flows:
			print("Timestamp: " + str(flow.timeStamp))
			print("Source Address:  " + flow.srcAddr + ", " + "Destination Address: " + flow.destAddr)
			print("Source Port: " + flow.srcPort + ", " + "Destination Port: " + flow.destPort + ", " + "Protocol : " + flow.protocol)
			print("Packets Sent: " + str(flow.pktSent) + ", " + "Packets Received: " + str(flow.pktRecv) + ", " + "Bytes Sent: " + str(flow.bytesTr) + ", " + "Bytes Received: " + str(flow.bytesRecv))
			print("Label: Unknown")
			print("\n")
 

def main():

	filenum = 1
	burstList = []

	for file in sys.argv[1:]:
		lastTime = 0
		pktcount = 0
		id = 1
		packets = pyshark.FileCapture(file)
		for pkt in packets:
			# flow match
			match = 0

			# set t ime
			timesecs = pkt.sniff_time.second*1000000 + pkt.sniff_time.microsecond

			# add create burst if new or timeout of 1s occurs
			if id == 1 or timesecs - lastTime > 1000000:
				burst = Burst(id, timesecs, filenum)
				id += 1
				burstList.append(burst)
			
			# update time	
			lastTime = timesecs

			# add first flow and continue to next pkt
			if len(burst.flows) == 0:
				newFlow = create_flow(pkt)
				flow = newFlow 
				burst.flows.append(newFlow)
				continue

			# check if newFlow exists in burst
			for flow in burst.flows:
				if "192.168.12" not in pkt.ip.src:
					if (flow.destAddr == pkt.ip.src):
						# update
						match = 1 
				elif "192.168.12" in pkt.ip.src:
					if (flow.destAddr == pkt.ip.dst):
						# update
						match = 1

			# create if no match
			if match is 0:
				newFlow = create_flow(timesecs, pkt)
				flow = newFlow
				burst.flows.append(newFlow)

			# update if match
			else:
				burst.flows = update_flows(pkt, burst.flows)

			# vector shit		
			# ml function

		packets.close()
		filenum += 1

	print_bursts(burstList)

main()