
#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct


from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from gvt_header_l2 import GvtProtocol

from threading import Thread

from scapy.all import sniff

import numpy as np

import argparse,sys,time,os


ETHERTYPE_GVT = 0x8666
TYPE_PROPOSAL = 1
TYPE_DELIVER = 0


gvt = 0


start_ppkt = 0
pid = 0
lat = np.array([])

def handle_pkt(pkt):
        global lat
        global start_ppkt
        global gvt

        sys.stdout.flush()
#       pkt.show2()
       	#print "receive"

        end = time.time()
        print end - start_ppkt
        gvt = pkt[GvtProtocol].value
  	sys.stdout.flush()
        	#print end
#        	lat = np.append(lat, 1000*(end-start))
#       	print end-start
#            else:
##                start = time.time()
def receive():
    iface = 'enp1s0np1'
    #print "sniffing on %s" % iface
    sys.stdout.flush()
    build_lfilter = lambda (r): GvtProtocol in r and r[GvtProtocol].type == TYPE_DELIVER
    sniff(iface = iface, lfilter = build_lfilter,
          prn = lambda x: handle_pkt(x))

def send():
    global start_ppkt
    global gvt

    src_addr = socket.gethostbyname(sys.argv[1])
    dst_addr = socket.gethostbyname('10.50.0.100')
    iface = "enp1s0np1"
    
    lvt = 0
    end_simulation_loop = int(sys.argv[3])
    start = time.time()
    while lvt < end_simulation_loop:
        if lvt <= gvt:
	    lvt = lvt + 1
    	    #print "sending on interface %s to %s" % (iface, str(src_addr))
    	    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
    	    pkt = pkt / GvtProtocol(type=TYPE_PROPOSAL, value=lvt, pid=pid)
    	    #pkt.show2()
            start_ppkt = time.time()   
            sendp(pkt, iface=iface, verbose=False)

    end = time.time()
#   lat = np.append(lat, 1000*(end-start))
    print "total time: " + str(end-start)

    time.sleep(10) 

    os._exit(1)


 #   print("**************************************************")
 #   for l in lat:
 #       print("lat : " + str(l))   
#    print("avg: ", sum(lat)/len(lat))    
#    print len(lat)  

if __name__ == '__main__':
    if len(sys.argv)<4:
        print 'pass 2 arguments: <source> <pid> <size>'
        exit(1)

    pid = int(sys.argv[2])

    new_rec_thread = Thread(target=receive)
    new_rec_thread.start()

    new_send_thread = Thread(target=send)
    new_send_thread.start()
