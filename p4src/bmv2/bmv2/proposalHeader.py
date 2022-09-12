from scapy.all import *
import sys, os

TYPE_GVT = 0x600
TYPE_IPV4 = 0x800

class GvtProtocol(Packet):
    fields_desc = [    IntField("flag", 0),
                       IntField("value", 0),
                       IntField("pid", 0),
                       IntField("round", 0),
                       IntField("sid", 0)]

bind_layers(Ether, GvtProtocol, type=TYPE_GVT)
bind_layers(GvtProtocol, IP, type=TYPE_IPV4)
