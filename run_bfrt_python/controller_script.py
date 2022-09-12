table1 = bfrt.netgvt_l2_16.pipe.SwitchIngress.ipv4_lpm
entry = table1.entry_with_ipv4_forward(dst_addr=0x0a320106 , dst_mac=0xb8599fdf07cb, port="188").push()

entry = table1.entry_with_ipv4_forward(dst_addr=0x0a320101 , dst_mac=0x00154d1211a9, port="132").push()

table2 = bfrt.netgvt_l2_16.pipe.SwitchIngress.eth_forward
entry = table2.entry_with_gvt_forward(src_addr=0x00154d1211a9 , dst_mac=0x00154d1211a9, port="132").push()

bfrt.netgvt_l2_16.pipe.LVT_pid_0.dump(from_hw=True)
bfrt.netgvt_l2_16.pipe.LVT_pid_1.dump(from_hw=True)
bfrt.netgvt_l2_16.pipe.GVT.dump(from_hw=True)

bfrt.netgvt_l2_16.pipe.LVT_pid_1.add(0, 100000)
bfrt.netgvt_l2_16.pipe.LVT_pid_2.add(0, 100000)
bfrt.netgvt_l2_16.pipe.LVT_pid_3.add(0, 100000)
bfrt.netgvt_l2_16.pipe.LVT_pid_4.add(0, 100000)
bfrt.netgvt_l2_16.pipe.LVT_pid_5.add(0, 100000)
bfrt.netgvt_l2_16.pipe.LVT_pid_6.add(0, 100000)

mcf1 = bfrt.pre.node.add(999)
mcfg1 = entry(MGID = 999, MULTICAST_NODE_ID = [132,164]).push()



#Setup multicast group
multicast_grp = 1 #Match your p4
entry = bfrt.pre.node.entry(MULTICAST_NODE_ID = 1,MULTICAST_RID = 1,DEV_PORT = [68,140]).push() #List the ports your want to MC to
entry = bfrt.pre.mgid.entry(MGID = multicast_grp, MULTICAST_NODE_ID = [1,], MULTICAST_NODE_L1_XID_VALID = [False,],MULTICAST_NODE_L1_XID = [0, ]).push()


