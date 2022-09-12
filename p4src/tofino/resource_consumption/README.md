The NetGVT P4 program is written in P4-16 for the Tofino Native Architecture (TNA).

The P4 code has been tested on Intel P4 Studio 9.4.0.

For running NetGVT, first setup the SDE environment. Assuming the SDE environment is already running we can compile it.

> bf-p4c NetGVTapp.p4
> cp_p4 NetGVTapp

#Launch the switch

> $SDE/run_switchd.sh -p NetGVTapp &
