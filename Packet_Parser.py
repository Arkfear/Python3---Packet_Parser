import dpkt, pcap
import re
import sys
import binascii
import datetime
import time

pc = pcap.pcap()
for timestamp , packet in pc: 
    eth_header = binascii.b2a_hex(packet[0:14])
    ip_header = binascii.b2a_hex(packet[14:34])
    protocol_header = binascii.b2a_hex(packet[34:42])

    ### eth_decoder ###
    dst_mac = eth_header[0:12]
    src_mac = eth_header[12:24]
    netlayer_type = eth_header[24:28]
    ### ip_decoder ### 
    trans_type = ip_header[18:20]
    src_ip = ip_header[24:32]
    dst_ip = ip_header[32:40]
    TTL = ip_header[16:18]
    TOS = ip_header[2:4]
    checksum = ip_header[20:24]
    ### protocol_decoder ###
    src_port = protocol_header[0:4]
    dst_port = protocol_header[4:8]


    print "\n###################"
    print "TimeStamp: "+datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')+" (UTC: "+str(timestamp)+ ")"
    print "Total length of packet: ",len(packet)
    print "Ethernet II:"
    print "    Src_MAC: "+src_mac[0:2]+":"+src_mac[2:4]+":"+src_mac[4:6]+":"+src_mac[6:8]+":"+src_mac[8:10]+":"+src_mac[10:12]
    print "    Dst_MAC: "+dst_mac[0:2]+":"+dst_mac[2:4]+":"+dst_mac[4:6]+":"+dst_mac[6:8]+":"+dst_mac[8:10]+":"+dst_mac[10:12]
    if(str(netlayer_type) == "0800" ):
      print "    Type: "+"IP"+"(0x0800)"

    print "---------------------------"
    print "Internet Protocol:"
    print "    Header Length: 20 bytes"
    print "    Total Length: "
    print "    Version: 4"
    print "    Src_IP: "+str(int(src_ip[0:2],16))+"."+str(int(src_ip[2:4],16))+"."+str(int(src_ip[4:6],16))+"."+str(int(src_ip[6:8],16))
    print "    Dst_IP: "+str(int(dst_ip[0:2],16))+"."+str(int(dst_ip[2:4],16))+"."+str(int(dst_ip[4:6],16))+"."+str(int(dst_ip[6:8],16))
    print "    Protocol: "
    print "    TTL: "+str(int(TTL,16))+" TOS: 0x"+str(TOS)
    print "    Checksum: 0x"+str(checksum)

    print "---------------------------"
    print "Transport Protocol:"

    if str(trans_type) == "06":
        print "    Protocol: TCP (0x"+str(trans_type)+")"
    elif str(trans_type) == "11":
        print "    Protocol: UDP (0x"+str(trans_type)+")"
    else :
        print "    Protocol: 0x"+str(trans_type)
    print "    Src_Port: "+str(int(src_port,16))
    print "    Dst_Port: "+str(int(dst_port,16))
    
    print "###################\n"
