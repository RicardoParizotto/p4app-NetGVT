#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import threading
import time 
import thread

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from proposalHeader import GvtProtocol
from receive import *

TYPE_PROP = 0x1919
TYPE_REQ = 0x1515
TYPE_GVT = 0x600
TYPE_DEL = 0x1313
TYPE_PREPARE = 0x3333
TYPE_PREPAREOK = 0x4444
TYPE_STARTCHANGE = 0x4343
TYPE_STARTVIEW = 0x4747
TYPE_FAILURE = 0x5555
TYPE_DELFAILURE = 0x6666
TYPE_VIEWCHANGE = 0x700
TYPE_RESENDPROP = 0x1919

class gvtControl:
    def __init__(self, dest_ip, pid):
        #creates socket to a destination 
        self.addr = socket.gethostbyname(dest_ip)
        self.iface = self.get_if()
        self.pid = pid
        self.dest_ip = dest_ip
        self.GVT_value = 0
        self.last_proposal = 0
        self.last_proposal_time = 0
        self.leader_alive = 1
        self.sent_but_not_yet_acknowledged = 0
        #interfaces
        self.time_map = {} 
        self.f = open("demofile.txt", "w")
        self.b = open("bufferfile.txt", "w")
        self.queue = []
        self.lock_alive = thread.allocate_lock()
        #gambia. One process start the synchronization.
        self.start_synchronization()

        #start receiver thread
        self.receivethread = threading.Thread(target=self.receiveThread)
        self.receivethread.start()

        #just for debugging
        #start run loop
        self.run_loop = threading.Thread(target=self.runThread)
        self.run_loop.start()

        self.alive = threading.Thread(target=self.aliveThread)
        self.alive.start()

        self.send = threading.Thread(target=self.send_queue)
        self.send.start()

    def start_synchronization(self):
        #this not right. A separeted process should init that.
        if(self.pid == 1):
            pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
            pkt = pkt / GvtProtocol(flag = TYPE_REQ, value=0, pid= self.pid)
            sendp(pkt, iface=self.iface, verbose=False)


    def receiveThread(self):
        #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        #iface = ifaces[0]
        print "sniffing on %s" % self.iface
        sys.stdout.flush()
        sniff(iface = self.iface, prn = lambda x: self.handle_pkt(x))
        #TODO: Change this interface after the failure

    def handle_pkt(self, pkt):
        if GvtProtocol in pkt:
            #print "receive"
            if pkt[GvtProtocol].flag == TYPE_DEL:              #delivering new GVT value for the server
                self.GVT_value = pkt[GvtProtocol].value
                print "got new value: " + str(self.GVT_value)
                #DEBUG
                update_time = time.time() - self.last_proposal_time
                #print "time: " + str(time.time() - self.last_proposal_time)
                print("time: " + str(update_time))  #just work for new experiments

                #acknowledges the message
                self.f.write(str(update_time) + "\n")
                self.f.flush()
                self.b.write(str(len(self.queue)) + "\n")
                self.b.flush()
                if self.GVT_value == self.sent_but_not_yet_acknowledged and pkt[GvtProtocol].pid == self.pid :
                    self.sent_but_not_yet_acknowledged = 0
                #what should i do with this new value    

            elif pkt[GvtProtocol].flag == TYPE_DELFAILURE:   #this is a PONG! Primary is Alive bb!
                #print "pong"
                self.lock_alive.acquire()
                self.leader_alive = 1
                self.lock_alive.release()

            elif pkt[GvtProtocol].flag ==  TYPE_STARTVIEW:
                #RE0END PACKETS for packet sent but not yet received
                print('start view!!!')
                self.send_packet(flag_operation=TYPE_PROP, message_value=int(self.sent_but_not_yet_acknowledged), process_pid=self.pid)
                self.resend_old_messages()
        sys.stdout.flush()

    def change_interface(self):
        print('PRIMARY TIMEOUT!!!' + str(self.ifs))
        for i in self.ifs:
            if i:
                self.iface = i
                self.ifs.remove(i)
                break
        self.receivethread = threading.Thread(target=self.receiveThread)
        self.receivethread.start()
        self.resend_old_messages()

    def resend_old_messages(self):
        #so esta mandando uma mensagem no momento
        #TODO: armazenar e reenviar todas as mensagens da aplicacao
        if(self.sent_but_not_yet_acknowledged):
        	print("REENVIANDO")
        	print(self.sent_but_not_yet_acknowledged)
        	self.send_packet(flag_operation=TYPE_PROP, message_value=int(self.sent_but_not_yet_acknowledged), process_pid=self.pid)


    def get_if(self):
        self.ifs=get_if_list()
        iface=None # "h1-eth0"
        for i in get_if_list():
            if "eth0" in i:
                iface=i
                break;
        if not iface:
            print "Cannot find eth0 interface"
            exit(1)
        self.ifs.remove('lo')
        self.ifs.remove('eth0')
        print(self.ifs)
        return iface

    def send_packet(self, flag_operation, message_value, process_pid):
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
        pkt = pkt / GvtProtocol(flag = flag_operation, value=message_value, pid = process_pid)
        pkt = pkt /IP(dst=self.addr) / TCP(dport=1234, sport=random.randint(49152,65535))
        sendp(pkt, iface=self.iface, verbose=False)

    def build_proposal(self, proposal_value):
        self.last_proposal = int(proposal_value)
        self.send_packet(flag_operation=TYPE_PROP, message_value=int(proposal_value), process_pid=self.pid)

    #this thread implements a run loop. Just for writing LVT values as a debug functionality 
    def runThread(self):
        value = 1    
        while True:
            #0.1 ---- 1 ------ 100
            time.sleep(1)     
            print "sending on interface %s to %s" % (self.iface, str(self.addr))
            #TODO: We need to enforce the concurrency control here
            self.queue.append([value, time.time()])
            self.time_map[value] = time.time()
            value = value + 1

    def aliveThread(self):
        while True:
            time.sleep(5)
            self.lock_alive.acquire()
            if(self.leader_alive == 1):
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
                pkt = pkt / GvtProtocol(flag = TYPE_FAILURE, value=0, pid= self.pid)
                sendp(pkt, iface=self.iface, verbose=False)           #this is a PING! leader alive?
                self.leader_alive = 0
                #print "ping"
            else:
                #trigger recovery...
                self.change_interface() 
                self.leader_alive = 1 #necessario para nao entrar nessa condicao logo que o novo leader e escolhido
                #envia pacote de start changeS
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
                pkt = pkt / GvtProtocol(flag = TYPE_VIEWCHANGE, value=0, pid= self.pid)
                sendp(pkt, iface=self.iface, verbose=False) 
            self.lock_alive.release()

    def send_queue(self):
        #TODO: concurrency control
        while True:
            if(self.sent_but_not_yet_acknowledged == 0 and len(self.queue) > 0):
                get = self.queue.pop(0)
                self.sent_but_not_yet_acknowledged = get[0]
                print self.sent_but_not_yet_acknowledged
                self.last_proposal_time = get[1]
                self.build_proposal(proposal_value=self.sent_but_not_yet_acknowledged)          

def main():    
    if len(sys.argv)<3:
        #TODO: Does not make sense this Dest IP. Solve it 
        print 'pass 2 arguments: <destination_ip> <pid>'
        exit(1)

    GVTcontrol_instance = gvtControl(sys.argv[1], int(sys.argv[2]))

if __name__ == '__main__':
    main()
