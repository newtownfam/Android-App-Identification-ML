
#!/usr/bin/python

# calculate print per-flow stats:
#	<timestamp> <src addr> <dst addr> <src port> <dst port> <proto>\
#	<#packets sent> <#packets rcvd> <#bytes send> <#bytes rcvd>

# Sample Script: http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html


####### Capture Packets ########


# import modules
import socket 
import struct
import binascii
import os
import pye

# print author details on terminal
print pye.__author__

# if operating system is windows
if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("YOUR_INTERFACE_IP",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# if operating system is linux
else:
    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

# create loop 
while True:

    # Capture packets from network
    pkt=s.recvfrom(65565)

    # extract packets with the help of pye.unpack class 
    unpack=pye.unpack()

    print "\n\n===&gt;&gt; [+] ------------ Ethernet Header----- [+]"

    # print data on terminal
    for i in unpack.eth_header(pkt[0][0:14]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),
    print "\n===&gt;&gt; [+] ------------ IP Header ------------[+]"
    for i in unpack.ip_header(pkt[0][14:34]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),
    print "\n===&gt;&gt; [+] ------------ Tcp Header ----------- [+]"
    for  i in unpack.tcp_header(pkt[0][34:54]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),


##### Extract Captured Data #####


import socket, struct, binascii

class unpack:
 def __cinit__(self):
  self.data=None

 # Ethernet Header
 def eth_header(self, data):
  storeobj=data
  storeobj=struct.unpack("!6s6sH",storeobj)
  destination_mac=binascii.hexlify(storeobj[0])
  source_mac=binascii.hexlify(storeobj[1])
  eth_protocol=storeobj[2]
  data={"Destination Mac":destination_mac,
  "Source Mac":source_mac,
  "Protocol":eth_protocol}
  return data

 # ICMP HEADER Extraction
 def icmp_header(self, data):
  icmph=struct.unpack('!BBH', data)
  icmp_type = icmph[0]
  code = icmph[1]
  checksum = icmph[2]
  data={'ICMP Type':icmp_type,
  "Code":code,
  "CheckSum":checksum}
  return data

 # UDP Header Extraction
 def udp_header(self, data):
  storeobj=struct.unpack('!HHHH', data)
  source_port = storeobj[0]
  dest_port = storeobj[1]
  length = storeobj[2]
  checksum = storeobj[3]
  data={"Source Port":source_port,
  "Destination Port":dest_port,
  "Length":length,
  "CheckSum":checksum}
  return data

 # IP Header Extraction
 def ip_header(self, data):
  storeobj=struct.unpack("!BBHHHBBH4s4s", data)
  _protocol =storeobj[6]
  _source_address =socket.inet_ntoa(storeobj[8])
  _destination_address =socket.inet_ntoa(storeobj[9])

  data={ "Source Address":_source_address,
  "Destination Address":_destination_address,
  "Protocol":_protocol}
  
  return data

 # Tcp Header Extraction
 def tcp_header(self, data):
  storeobj=struct.unpack('!HHLLBBHHH',data)
  _source_port =storeobj[0] 
  _destination_port  =storeobj[1]
  _sequence_number  =storeobj[2]
  _acknowledge_number  =storeobj[3]
  _offset_reserved  =storeobj[4]
  _tcp_flag  =storeobj[5]
  _window  =storeobj[6]
  _checksum  =storeobj[7]
  _urgent_pointer =storeobj[8]
  data={"Source Port":_source_port,
  "Destination Port":_destination_port,
  "Sequence Number":_sequence_number,
  "Acknowledge Number":_acknowledge_number,
  "Offset & Reserved":_offset_reserved,
  "Tcp Flag":_tcp_flag,
  "Window":_window,
  "CheckSum":_checksum,
  "Urgent Pointer":_urgent_pointer
  }
  return data 

# Mac Address Formating
def mac_formater(a):
 b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
 return b

def get_host(q):
 try:
  k=socket.gethostbyaddr(q)
 except:
  k='Unknown'
 return k