/*Never forget: components/processes are indexed by their id [0..n - 1]. 
*/

#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parser.p4"


register<bit<32>>(TOTAL_NUMBER_OF_PROCESSES) LvtValues;
register<bit<32>>(1) GVT;
register<bit<32>>(1) PrepareOk;
register<bit<32>>(1) RoundNumber;
register<bit<32>>(1000) RoundControl;
register<egressSpec_t>(1) primary_port;
register<bit<32>>(1) DoChangeNumber;
register<bit<32>>(1) LeaderId;

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action answer_replica(egressSpec_t port){
        standard_metadata.egress_spec = port;  
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action start_execution(){
      GVT.write(0, 0);
      LvtValues.write(0, 0);
      LvtValues.write(1, 0);
      PrepareOk.write(0, 0);
      RoundNumber.write(0, 0);
    }

    action multicast(bit<32> grp_id) {
      standard_metadata.mcast_grp = (bit<16>) grp_id;
    }

    action send_message(egressSpec_t port) {
      standard_metadata.egress_spec = port;
    }

    action set_id(bit<32> switch_id){
      hdr.gvt.sid = switch_id;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table set_primary {
      key = {
        meta.primary: exact;
      }
      actions = {
         answer_replica;
      }
      size = 10;
    }

    table this_switch {
      key = {
         hdr.gvt.sid: exact; 
      }
      actions = {
        set_id;
      }
      size = 10;
    }

    table this_switch_2 {
      key = {
         hdr.gvt.sid: exact; 
      }
      actions = {
        set_id;
      }
      size = 10;
    }

    table set_destination {
      key = {
         hdr.gvt.pid: exact;
      }
      actions = {
        send_message;
      }
      size = 20;     /*each process needs one entry*/
    }

    table set_switch_dest {
      key = {
        hdr.gvt.sid: exact;
      }
      actions = {
        send_message;
      }
      size = 20;
    }
    
    apply {
        if(hdr.gvt.isValid()){
          if( hdr.gvt.type == TYPE_FAILURE){                      /*if is a probe message just answer it */
             hdr.gvt.type = TYPE_DELFAILURE;
            set_destination.apply();                              //i'm not dead, bro. Just bored. Relax!
          } else if ((hdr.gvt.type == TYPE_PROP || hdr.gvt.type == TYPE_PREPARE) && meta.iterator == 0){
            /*if is a server proposal or a prepare message. Both case are equivalent
            but the first is a message recived from servers an the latter, TYPE_PREPARE, is for replicas*/
            GVT.read(meta.currentGVT, 0);
            if (meta.currentGVT <= hdr.gvt.value) {                /*check for conditions to start a new gvt computation*/
                LvtValues.write(hdr.gvt.pid, hdr.gvt.value);      //store the process LVT
                meta.iterator = 1;                                //trigger metadata to start GVT calculation
            } else {                                              /*If the value is less or equal to the GVT we dont need to check anything, just drop it*/
              drop();
            }
          } else if(hdr.gvt.type == TYPE_PREPAREOK){              /*if is acknoledgment message from replicas, TYPE_PREPAREOK*/  
                RoundControl.read( meta.numPrepareOks, hdr.gvt.round);
                meta.numPrepareOks = meta.numPrepareOks + 1;
                RoundControl.write (hdr.gvt.round, meta.numPrepareOks);
                if(meta.numPrepareOks >= MAJORITY){
                  hdr.gvt.type = TYPE_DEL;
                  GVT.read(hdr.gvt.value, 0);
                  multicast(1);
                }
           } else if(hdr.gvt.type == TYPE_VIEWCHANGE || hdr.gvt.type == TYPE_REQ){
               /*TODO: ensure that other start changes does not init while one is active*/
               hdr.gvt.type = TYPE_STARTCHANGE;
               DoChangeNumber.write (0, 0);
               this_switch.apply();                                 //attaches the switch ID into the message
               multicast(2);                                        //send a start_change for all the replicas. Multicast group is defined statically in the control plane
           } else if (hdr.gvt.type == TYPE_STARTCHANGE){
                hdr.gvt.type = TYPE_MAKECHANGE;                   
                LeaderId.write(0, hdr.gvt.sid);                     /*update the primary ID*/
                set_switch_dest.apply();                            //set the destination based on the incomming packet source
           } else if(hdr.gvt.type == TYPE_MAKECHANGE){
                DoChangeNumber.read( meta.numDoChanges, 0);
                meta.numDoChanges = meta.numDoChanges + 1;
                DoChangeNumber.write (0, meta.numDoChanges);
                if(meta.numDoChanges >= MAJORITY){                      /*wait for the maximum and them sends the star view for servers*/
                  /*TODO: we need to send a startview both for servers and then servers resend old proposals */ 
                  /*TODO: we also need to identify how to compute old values*/
                  hdr.gvt.type = TYPE_STARTVIEW;               
                  multicast(1);                                         //this multicast group does not need to change
                }
           }
          if(meta.iterator > 0 ){                                       /*this condition is to start the GVT computation*/ 
              if(meta.iterator == 1){                                   /*if is the first iteration*/
                LvtValues.read(meta.minLVT, 0); 
                GVT.read(meta.currentGVT, 0);     
              }
              /*we do not consider a scenario with zero processes */
              LvtValues.read(meta.readedValue, meta.iterator);
              if(meta.readedValue < meta.minLVT){                        /*selecting the less gvt time*/
                meta.minLVT = meta.readedValue;
              }
              meta.iterator = meta.iterator + 1;                         /*iterates through the register array*/
              if(meta.iterator == TOTAL_NUMBER_OF_PROCESSES){            /*if it is the last iteration*/
                    GVT.write(0, meta.minLVT);                           /*update GVT and multicast the new value for replicas*/
                    if (hdr.gvt.type == TYPE_PREPARE){
                      hdr.gvt.type = TYPE_PREPAREOK;
                      LeaderId.read(meta.primary, 0);
                      set_primary.apply();                               //the primary is defined using the received switch id to determine an output port
                    } else {                                             /*the other case is the hdr.gvt.value is propose*/                                          
                        RoundNumber.read(meta.currentRound, 0);          /*append round number to the header and reset the history of PREPAREOKS*/
                        RoundNumber.write(0, meta.currentRound + 1);
                        hdr.gvt.round = meta.currentRound + 1;
                        hdr.gvt.type = TYPE_PREPARE;
                        this_switch_2.apply();  
                        multicast(2);                                    /*send for replicas*/
                    }
              } else {
                resubmit(meta); 
              }
          }
        }
        /*TODO: deliver packet to end host */
        /*
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }*/
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {    } 
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
      apply {
      update_checksum(
      hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;