from scapy.all import *
import sys, os

TYPE_GVT = 0x8666
TYPE_IPV4 = 0x800

class GvtProtocol(Packet):
    fields_desc = [IntField("type", 0), IntField("pid", 0), IntField("value", 0)]

bind_layers(Ether, GvtProtocol, type=TYPE_GVT)
bind_layers(GvtProtocol, IP, type=TYPE_IPV4)
