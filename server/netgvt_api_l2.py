
#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import os


from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from gvt_header_l2 import GvtProtocol

import threading
from threading import Thread

from scapy.all import sniff

import numpy as np

import argparse,sys,time,os


ETHERTYPE_GVT = 0x8666
TYPE_PROPOSAL = 1
TYPE_DELIVER = 0
ASYNCHRONOUS = "async"
SYNCHRONOUS = "sync"


gvt = 0
n_processes = 0
start_ppkt = 0
pid = 0
lat = np.array([])
lvt = 0
mode = ASYNCHRONOUS

directory = os.getcwd()


lock = threading.Lock()


def handle_pkt(pkt):
        global lat
        global start_ppkt
        global gvt
        global lvt
        global lock

        sys.stdout.flush()
#       pkt.show2()
       	#print "receive"

        end = time.time()
        print(end - start_ppkt)
        gvt = pkt[GvtProtocol].gvt
        sys.stdout.flush()
        
        
        print(lvt)
        print(pkt[GvtProtocol].value)
        lock.acquire()
        if lvt > pkt[GvtProtocol].value:
            print("rollback")
            lvt = gvt
        lock.release()
             

def receive(iface):
    #print "sniffing on %s" % iface
    sys.stdout.flush()
    build_lfilter = lambda r: GvtProtocol in r and r[GvtProtocol].type == TYPE_DELIVER
    sniff(iface = iface, lfilter = build_lfilter,
          prn = lambda x: handle_pkt(x))

def send(iface, end_time):
    global start_ppkt
    global gvt
    global lvt
    global mode
    global lock
    global n_processes
    

    end_simulation_loop = end_time
    start = time.time()
    while lvt < end_simulation_loop:
        time.sleep(0.1) 
        lock.acquire()
        if mode==ASYNCHRONOUS or lvt <= gvt:
            event_t = random.randint(1, 10) if mode == ASYNCHRONOUS else 1
            lvt = lvt + event_t
            #print "sending on interface %s to %s" % (iface, str(src_addr))
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type = ETHERTYPE_GVT)
            pkt = pkt / GvtProtocol(type=TYPE_PROPOSAL, value=lvt, pid=pid, gvt=0, rec_control=0)
            #pkt.show2()
            #print(lvt)
            start_ppkt = time.time()   
            sendp(pkt, iface=iface, verbose=False)
        lock.release()

    end = time.time()
#   lat = np.append(lat, 1000*(end-start))
    total = str(end-start)
    print("total time: " + total)


    file = open(f"/home/p4/p4app-NetGVT/results/drec_{mode}_pid{str(pid)}{str(n_processes)}_size{str(end_time)}.txt", "a+")
    file.write("total time, " + total + "\n") 
    file.close()

    time.sleep(10) 

    os._exit(1)


parser = argparse.ArgumentParser(description='Optional app description')



# Required positional argument
parser.add_argument('np', type=int,
                    help='A required number corresponding to the total number of processes')

# Required positional argument
parser.add_argument('pid', type=int,
                    help='A required identification for logical process')


# Required positional argument
parser.add_argument('size', type=int,
                    help='A required number corresponding to the total simulation time')

# Required positional argument
parser.add_argument('iface', type=str,
                    help='A required string corresponding to the interface')


# Required positional argument
parser.add_argument(
    "mode",
    choices=["sync", "async"],
    help="Chose the sync operation mode: 'sync' ou 'async'."
)

if __name__ == '__main__':

    args = parser.parse_args()
  
    pid = args.pid
    iface = args.iface
    mode = args.mode
    n_processes = args.np

    new_rec_thread = Thread(target=receive, args=(iface,))
    new_rec_thread.start()

    new_send_thread = Thread(target=send, args=(iface, args.size,))
    new_send_thread.start()
