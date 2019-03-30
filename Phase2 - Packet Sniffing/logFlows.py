import socket
from struct import *
import datetime
import pcapy
import sys

def main():
        #list all devices
        devices = pcapy.findalldevs()
        print devices

        #show available devices
        print "Available devices are :"
        for d in devices :
                print d

        print "Sniffing packets from android box via eth1"

        '''
        open device
        # Arguments here are:
        #   device
        #   snaplen (maximum number of bytes to capture _per_packet_)
        #   promiscious mode (1 for true)
        #   timeout (in milliseconds)
        '''
        cap = pcapy.open_live("eth1" , 65536 , 0 , 0)

        #start sniffing packets
        while(1) :
                (header, packet) = cap.next()
                #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
                parse_packet(packet)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

#function to parse a packet
def parse_packet(packet) :

        #parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
     
        #Parse IP packets, IP Protocol number = 8

        if eth_protocol == 8 :
                #Parse IP header
                #take first 20 characters for the ip header
                ip_header = packet[eth_length:20+eth_length]

                #now unpack them :)
                iph = unpack('!BBHHHBBH4s4s' , ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4

                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8]);
                d_addr = socket.inet_ntoa(iph[9]);

                print 'Source Address: ' + str(s_addr) + ' ' + 'Destination Address: ' + str(d_addr)
                
                #TCP protocol
                if protocol == 6 :
                        t = iph_length + eth_length
                        tcp_header = packet[t:t+20]

                        #now unpack them :)
                        tcph = unpack('!HHLLBBHHH' , tcp_header)

                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4

                        print 'Source Port: ' + str(source_port) + ' ' + 'Dest Port: ' + str(dest_port) + ' ' + 'Protocol: TCP'
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        print 'Data Size: ' + str(data_size)


                #UDP packets
                elif protocol == 17 :
                        u = iph_length + eth_length
                        udph_length = 8
                        udp_header = packet[u:u+8]

                        #now unpack them :)
                        udph = unpack('!HHHH' , udp_header)

                        source_port = udph[0]
                        dest_port = udph[1]
                        length = udph[2]
                        checksum = udph[3]

                        #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
                        print 'Source Port : ' + str(source_port) + ' ' + 'Dest Port : ' + str(dest_port) + ' ' + 'Protocol : UDP'

                        h_size = eth_length + iph_length + udph_length
                        data_size = len(packet) - h_size

                        print 'Data Size: ' + str(data_size)

main()


