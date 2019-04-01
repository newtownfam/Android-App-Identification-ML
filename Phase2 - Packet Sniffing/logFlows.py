'''
CS AdvNetworks
Phase 2
Peter Christakos
Andrew Morrison

'''

import socket
from struct import *
import datetime
import pcapy
import sys
from threading import Thread
import threading

# obj to hold a connection
class Connection:
    def __init__(self, srcAddr, destAddr, srcPort, destPort, bytesTr, bytesRecv, pktSent, pktRecv, startTime, timeout, protocol):
        self.srcAddr = srcAddr
        self.destAddr = destAddr
        self.srcPort = srcPort
        self.destPort = destPort
        self.bytesTr = bytesTr
        self.bytesRecv = bytesRecv
        self.pktSent = pktSent
        self.pktRecv = pktRecv
        self.startTime = startTime
        self.timeout = timeout
        self.protocol = protocol

# global list to hold connections
Connections = []

def main():
        #list all devices
        devices = pcapy.findalldevs()
        print "available devices are: "
        print devices
        print "\n"
        print "sniffing packets from android box via eth1..."

        cap = pcapy.open_live("eth1" , 65536 , 0 , 0)

        # run thread to constantly print completed flows 
    
        printfl = Thread(target = print_flow, args = ())
        
        # this causes the thread to close but it is not a clean exit
        printfl.daemon = True
  
        printfl.start()

        # loop through to parse packets
        while(1) :    
            (header, packet) = cap.next()
            read_packet(header, packet)        

def print_flow():
    while(1):
        for i in Connections:
            delta = datetime.datetime.now() - i.timeout
            if (int(delta.total_seconds()) >= 1):
                    print "Flow completed with: \n"
                    print "Timestamp: " + str(i.startTime)
                    print "Source Address:  " + i.srcAddr + ", " + "Destination Address: " + i.destAddr
                    print "Source Port: " + i.srcPort + ", " + "Destination Port: " + i.destPort + ", " + "Protocol : " + i.protocol
                    print "Packets Sent: " + str(i.pktSent) + ", " + "Packets Received: " + str(i.pktRecv) + ", " + "Bytes Sent: " + str(i.bytesTr) + ", " + "Bytes Received: " + str(i.bytesRecv)
                    print "Timeout Time: %i seconds" %(int(delta.total_seconds()))
                    print "\n"
                    Connections.remove(i)

#function to parse a packet
def read_packet(header, packet) :

        connection = None
        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
     
        #Parse IP packets

        if eth_protocol == 8 :
                ip_header = packet[eth_length:20+eth_length]
                iph = unpack('!BBHHHBBH4s4s' , ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8]);
                d_addr = socket.inet_ntoa(iph[9]);

                
                #TCP protocol
                if protocol == 6 :
                        # get source and dest port
                        t = iph_length + eth_length
                        tcp_header = packet[t:t+20]
                        tcph = unpack('!HHLLBBHHH' , tcp_header)
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        
                        connection = Connection(str(s_addr), str(d_addr), str(source_port), str(dest_port), header.getlen(), 0, 1, 0, datetime.datetime.now(), datetime.datetime.now(), "TCP")             


                #UDP Protocol
                elif protocol == 17 :
                        # get source and dest port
                        u = iph_length + eth_length
                        udph_length = 8
                        udp_header = packet[u:u+8]
                        udph = unpack('!HHHH' , udp_header)
                        source_port = udph[0]
                        dest_port = udph[1]
            
                        connection = Connection(str(s_addr), str(d_addr), str(source_port), str(dest_port), header.getlen(), 0, 1, 0, datetime.datetime.now(), datetime.datetime.now(), "UDP")

                                      
                # append to connections array
                if connection is not None:
                    #print header.getlen()
                    match = 0
                    if len(Connections) == 0:
                            if "192.168.12" in connection.srcAddr: 
                                    Connections.append(connection)
                                    match = 1
                    else:
                            for i in Connections:
                                    if "192.168.12" not in connection.srcAddr:
                                            # recv
                                            if (i.destAddr == connection.srcAddr) and (i.destPort == connection.srcPort) and (i.protocol == connection.protocol):
                                                    #update connection
                                                    i.bytesRecv += header.getlen()
                                                    i.timeout = datetime.datetime.now()
                                                    i.pktRecv += 1
                                                    match = 1
            
                                    elif "192.168.12" in connection.srcAddr:
                                            # transmitting
                                            if (i.destAddr == connection.destAddr) and (i.destPort == connection.destPort) and (i.protocol == connection.protocol):
                                                    #update connection
                                                    i.bytesTr += header.getlen()
                                                    i.timeout = datetime.datetime.now()
                                                    i.pktSent += 1
                                                    match = 1
                                                   
                    if match == 0:
                            if "192.168.12" in connection.srcAddr: 
                                    Connections.append(connection)           


main()


