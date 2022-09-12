
# This is the main repository for NetGVT. 

The system is configured with two hosts, each running a processes. 

To run a simple experiement, try:

> make

This will deploy the configuration from the topology and the scripts for each switch.  

> xterm h1 h2

Running xterm will open a prompt for two hosts h1, and h2. Next you can navigate to the prompt of each host
and run 

> python gvt_control.py 10.0.0.0  0
> python gvt_control.py 10.0.0.0. 1 

Then you can type the new LVT values. The system will always return the updated global virtual time.

# Integration into existing simulators

You can integrate NetGVT into an existing distributed simulator by importing into the simulator
communication interface the gvt control API.

> import gvtControl

Than just instatiate an gvtControl object

>  GVTcontrol_instance  = gvtControl(ip_address, process_id)

When the process have to propose an LVT value, it can simply to call a gvtControl
method 

> GVTcontrol_instance.put(LVT)

Finally, when the simulator desires to obtain a new GVT value, just get it from the GvtControl

> GVTcontro_instance.get()

Ideally, this method will return a value only when there is a new GVT value.




