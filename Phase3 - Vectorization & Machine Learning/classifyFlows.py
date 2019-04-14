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
	flows = []
	def __init__(self, id, time):
		self.id = id
		self.time = time

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

def create_flow(timesecs, pkt):
	# if sent, add to packets sent
	if '192.168.12' in pkt.ip.src:	
		flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, pkt.length, 0, 1, 0, timesecs, pkt.transport_layer)
	# else, add to packets recv
	else:
		flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, 0, pkt.length, 0, 1, timesecs, pkt.transport_layer)
	return flow


def update_flows(pkt, flows):
	for flow in flows:
		if "192.168.12" not in newFlow.srcAddr:
			# incr recv
			if (flow.destAddr == newFlow.srcAddr) and (flow.destPort == newFlow.srcportc) and (flow.protocol == newFlow.protocol):
				#update connection
				flow.bytesRecv += pkt.length
				#flow.timeout = # TODO
				flow.pktRecv += 1
				match = 1
		elif "192.168.12" in newFlow.srcAddr:
			# incr tr
			if (flow.destAddr == newFlow.destAddr) and (flow.destPort == newFlow.destPort) and (flow.protocol == newFlow.protocol):
				#update connection
				flow.bytesTr += pkt.length
				#flow.timeout = # TODO
				flow.pktSent += 1
				match = 1
	return flows


def main():

	id = 0
	burst = None
	burstList = []
	lastTime = 0
	found = False

	for file in sys.argv[1:]:
		packets = pyshark.FileCapture(file)
		for pkt in packets:
		
			# flow match
			match = 0

			# set t ime
			timesecs = pkt.sniff_time.second*1000000 + pkt.sniff_time.microsecond

			# add create burst if new or timeout of 1s occurs
			if id == 0 or timesecs - lastTime > 1000000:
				burst = Burst(id, timesecs)
				burstList.append(burst)

			# add first flow
			if len(burst.flows) == 0:
				newFlow = create_flow(timesecs, pkt)
				match = 1
			else:	
				burst.flows = update_Flows(pkt, burst.flows)
				match = 1

			if match is 0:
				if '192.168.12' in newFlow.srcAddr:
					burst.flows.append(newFlow)

			id += 1

main()