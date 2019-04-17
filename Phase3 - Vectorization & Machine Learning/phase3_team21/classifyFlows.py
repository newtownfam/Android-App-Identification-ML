'''
CS AdvNetworks
Phase 2
Peter Christakos
Andrew Morrison

'''
import pyshark
import sys
import datetime
import csv
from sklearn.svm import SVC
from sklearn import cluster
from sklearn import linear_model
from sklearn.externals import joblib
import numpy as np
import statistics
import random

# create a burst
class Burst:
	def __init__(self, id, time, filenum):
		self.id = id
		self.time = time
		self.flows = []
		self.filenum = filenum

# create a flow
class Flow:
	def __init__(self, srcAddr, destAddr, srcPort, destPort, bytesTr, bytesRecv, pktSent, pktRecv, startTime, endTime, protocol, ethtype, ttl, flags):
		self.srcAddr = srcAddr
		self.destAddr = destAddr
		self.srcPort = srcPort
		self.destPort = destPort
		self.bytesTr = bytesTr
		self.bytesRecv = bytesRecv
		self.pktSent = pktSent
		self.pktRecv = pktRecv
		self.startTime = startTime
		self.endTime = endTime
		self.protocol = protocol
		self.ethtype = ethtype
		self.ttl = ttl
		self.flags = flags
		self.packetLengths = []

def create_flow(pkt):
	# if sent, add to packets sent
	if '192.168.12' in pkt.ip.src:
		flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, int(pkt.length), 0, 1, 0, pkt.sniff_time, pkt.sniff_time, pkt.transport_layer, pkt.eth.type, pkt.ip.ttl, pkt.ip.flags)
		flow.packetLengths.append(int(pkt.length))
	# else, add to packets recv
	else:
		flow = Flow(pkt.ip.dst, pkt.ip.src, pkt[pkt.transport_layer].dstport, pkt[pkt.transport_layer].srcport, 0, int(pkt.length), 0, 1, pkt.sniff_time, pkt.sniff_time, pkt.transport_layer, pkt.eth.type, pkt.ip.ttl, pkt.ip.flags)
		flow.packetLengths.append(int(pkt.length))	
	return flow


def update_flows(pkt, flows):
	for flow in flows:
		if "192.168.12" not in pkt.ip.src:
			# incr recv
			if (flow.destAddr == pkt.ip.src) and (flow.destPort == pkt[pkt.transport_layer].srcport) and (flow.protocol == pkt.transport_layer):
				#update connection
				flow.bytesRecv += int(pkt.length)
				flow.pktRecv += 1
				flow.packetLengths.append(int(pkt.length))
				flow.endTime = pkt.sniff_time
		elif "192.168.12" in pkt.ip.src:
			# incr tr
			if (flow.destAddr == pkt.ip.dst) and (flow.destPort == pkt[pkt.transport_layer].dstport) and (flow.protocol == pkt.transport_layer):
				#update connection
				flow.bytesTr += int(pkt.length)
				flow.pktSent += 1
				flow.packetLengths.append(int(pkt.length))
				flow.endTime = pkt.sniff_time
	return flows

def print_bursts(burstList, svm, reg):

	# loop through all created bursts and flows
	for burst in burstList:
		print("File: " + str(burst.filenum) + ", Burst: " + str(burst.id))
		for flow in burst.flows:
			# create a vector for the current flow
			vector = np.array([])
			timediff = (flow.endTime - flow.startTime)
			vector = np.array([int(timediff.seconds*100000 + timediff.microseconds), int(flow.pktSent + flow.pktRecv), int(flow.bytesTr + flow.bytesRecv), int(flow.bytesTr + flow.bytesRecv)/int(flow.pktSent + flow.pktRecv)])
			
			# print out meta data
			print("Timestamp: " + str(flow.startTime))
			print("Source Address:  " + flow.srcAddr + ", " + "Destination Address: " + flow.destAddr)
			print("Source Port: " + flow.srcPort + ", " + "Destination Port: " + flow.destPort + ", " + "Protocol : " + flow.protocol)
			print("Packets Sent: " + str(flow.pktSent) + ", " + "Packets Received: "  + str(flow.pktRecv) + ", " + "Bytes Sent: " + str(flow.bytesTr) + ", " + "Bytes Received: " + str(flow.bytesRecv))
			
			if vector[0] is not None:
				
				#make a prediction
				svm_prediction = svm.predict([vector])
				reg_prediction = reg.predict([vector])

				print("SVM Label: " + svm_prediction[0])
				print("Lin Regr Label: " + reg_prediction[0])	

			# if the flow is too small to be accurately labeled
			else:
				print("Label: Unknown")
			print("\n")

# create a svm model
def svm_learn(trainingVectors, trainingLabels):
	svc = SVC(degree=2, gamma=1, coef0=0, probability=True)
	fitted = svc.fit(trainingVectors.astype("float"), trainingLabels.ravel())
	predict = svc.predict(trainingVectors)
	print("\nTotal SVM Score: ")
	print(svc.score(trainingVectors.astype("float"), trainingLabels))
	print("\n")
	return fitted

# create a regression model
def regression_learn(trainingVectors, trainingLabels):
	model = linear_model.LogisticRegression(multi_class='ovr', solver='liblinear')
	fitted = model.fit(trainingVectors.astype("float"), trainingLabels.ravel())
	predict = fitted.predict(trainingVectors.astype("float"))
	print("Total Linear Regression Score: ")
	print(fitted.score(trainingVectors.astype("float"), trainingLabels))
	print("\n")
	return fitted

def read_vectors():

	# training set
	trainingVectors = np.array([])
	trainingLabels = np.array([])
	testingLabels = np.array([])
	first = True
	# read the training file
	with open('/opt/training.csv') as csvfile:
		data = list(csv.reader(csvfile))
		row_count = sum(1 for row in data) - 1
		visited = list(range(1, row_count))
		while len(visited) > 0:
			i = random.choice(visited)
			visited.remove(i)
			row = data[i]
			if first:
				trainingVectors = np.array([row[1], row[2], row[6], str(int(row[6])/int(row[2]))])
				trainingLabels = np.array(row[0])
				first = False
				continue
			trainingVectors = np.vstack((trainingVectors, [row[1], row[2], row[6], str(int(row[6])/int(row[2]))]))
			trainingLabels = np.vstack((trainingLabels, row[0]))
	return trainingVectors, trainingLabels

def main(args):

	filenum = 1
	burstList = []

	# get training vectors and labels from csv
	trainingVectors, trainingLabels = read_vectors()

	# create all models
	svm = svm_learn(trainingVectors, trainingLabels)
	reg = regression_learn(trainingVectors, trainingLabels)

	# loop through given files
	for file in args:
		lastTime = 0
		pktcount = 0
		id = 1
		packets = pyshark.FileCapture(file)
		for pkt in packets:

			# if the packet is not UDP or TCP then skip it
			try:
					flow = Flow(pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport, int(pkt.length), 0, 1, 0, pkt.sniff_time, pkt.sniff_time, pkt.transport_layer, pkt.eth.type, pkt.ip.ttl, pkt.ip.flags)
			except AttributeError:
				continue


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
				newFlow = create_flow(pkt)
				flow = newFlow
				burst.flows.append(newFlow)

			# update if match
			else:
				burst.flows = update_flows(pkt, burst.flows)
		packets.close()
		filenum += 1

	# print out statistics and predict the app
	print_bursts(burstList, svm, reg)

	# return burstList for csv purposes
	return burstList


if __name__ == '__main__':
	import sys
	main(sys.argv[1:])

#main(sys.argv[1:])
