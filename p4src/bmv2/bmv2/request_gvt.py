#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import threading

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from proposalHeader import GvtProtocol
from receive import *

TYPE_PROP = 0x1919
TYPE_REQ = 0x1515


TYPE_GVT = 0x666

class receiveThread(threading.Thread):
    def run(self):
        ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        iface = ifaces[0]
        print "sniffing on %s" % iface
        sys.stdout.flush()
        sniff(iface = iface, prn = lambda x: handle_pkt(x))

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    if len(sys.argv)<5:
        print 'pass 4 arguments: <destination> "<message>" <pid> <lvt>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
    pkt = pkt / GvtProtocol(type = TYPE_REQ, pid = int(sys.argv[3]), lvt= int(sys.argv[4]), round=1)
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
