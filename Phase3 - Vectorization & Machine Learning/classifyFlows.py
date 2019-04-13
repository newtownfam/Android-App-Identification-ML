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
    def __init__(self, id, time):
    	self.id = id
    	self.time = time
    flows = []

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

def main():
	
	counter=0
	ipcounter=0
	tcpcounter=0
	udpcounter=0
	id = 0
	burst = None
	burstList = []
	lastTime = 0
	found = False

	for file in sys.argv[1:]:
		packets = pyshark.FileCapture(file)
		packets_Sent = 1
		packets_Recv = 1
		for pkt in packets:
			#newFlow = Flow(packet.ip.src, packet.ip.dst, packet[packet.transport_layer].srcport, 
			#	packet[packet.transport_layer].dstport, packet.transport_layer, 
			#	packet.sniff_timestamp, int(packet.length))
			#time = datetime.datetime.utcfromtimestamp(ts)
			#timesecs = time.second*1000000 + time.microsecond
			timesecs = pkt.sniff_time.second*1000000 + pkt.sniff_time.microsecond

			if id == 0 or timesecs - lastTime > 1000000:
				burst = Burst(id, timesecs)
				burstList.append(burst)

			# add first flow
			if len(burst.flows) == 0:
				# if sent, incr packets_sent
				if '192.168.12' in pkt.ip.src:	
					flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, 0, 0, packets_Sent, packets_Recv, timesecs, pkt.transport_layer)
					packets_Sent += 1
					# TODO INCR BYTES TR
				# else, incr packets recv
				else
					flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, 0, 0, packets_Sent, packets_Recv, timesecs, pkt.transport_layer)
					packets_Recv += 1
					# TODO INCR BYTES RECV

			id += 1

			print(len(burstList))
main()