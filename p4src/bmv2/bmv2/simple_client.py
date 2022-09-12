#!/usr/bin/env python
import argparse
import sys
import random
import time 

from gvt_control import GvtControl

reference_time = 0

def get_reference_time():
	reference_time = something...


def main():  
    if len(sys.argv)<3:
        #TODO: Does not make sense this Dest IP. Solve it 
        print 'pass 2 arguments: <destination_ip> <pid>'
        exit(1)

    GVTcontrol_instance = gvtControl(sys.argv[1], int(sys.argv[2]))

    lvt = 1

    while true:
        passed_time = time.time()
        if passed_time > reference_time:
        	break

    while True:
        time.sleep(5)
        GVTcontrol_instance.build_proposal(proposal_value=lvt)
        lvt = lvt + int(time);  #this will depend of the "type" of process


if __name__ == '__main__':
    main()
