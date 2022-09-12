#!/bin/bash

#Kill any running switch
pkill switchd

#Set environment vars
source /root/bin/set_sde.sh


bf-p4c netgvt_l2_16.p4
cp_p4 netgvt_l2_16


#Launch the switch
$SDE/run_switchd.sh -p netgvt_l2_16 &

#Wait to it to get setup
sleep 60

#Add the ports
$SDE/run_bfshell.sh -b $SDE/port_setup.py

#Add other control info

