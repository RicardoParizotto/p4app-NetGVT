/* -*- P4_16 -*- */

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) Intel Corporation
 * SPDX-License-Identifier: CC-BY-ND-4.0
 */



#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers_l2.p4"
#include "util.p4"


#define number_of_processes 5


struct metadata_t {
    bit<32> iterator_0;
    bit<32> iterator_1;
    bit<32> gvt;          
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    Checksum() ipv4_checksum;
    
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        ig_md.iterator_0 = 0;
        ig_md.iterator_1 = 0;
        ig_md.gvt = 0;        
        transition parse_ethernet;
    }
 
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_GVT : parse_gvt;
            default : reject;
        }
    }
    state parse_gvt {
    	pkt.extract(hdr.gvt);
    	transition accept;
    	
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);    
        ipv4_checksum.add(hdr.ipv4);
        transition accept;
    }
}



Register<bit<32>, _>(1) LVT_pid_0;
Register<bit<32>, _>(1) LVT_pid_1;
Register<bit<32>, _>(1) LVT_pid_2;
Register<bit<32>, _>(1) LVT_pid_3;
Register<bit<32>, _>(1) LVT_pid_4;
Register<bit<32>, _>(1) LVT_pid_5;
Register<bit<32>, _>(1) LVT_pid_6;
Register<bit<32>, _>(1) LVT_pid_7;
Register<bit<32>, _>(1) LVT_pid_8;
Register<bit<32>, _>(1) LVT_pid_9;
Register<bit<32>, _>(1) LVT_pid_10;
Register<bit<32>, _>(1) LVT_pid_11;
Register<bit<32>, _>(1) LVT_pid_12;
Register<bit<32>, _>(1) LVT_pid_13;
Register<bit<32>, _>(1) LVT_pid_14;
Register<bit<32>, _>(1) LVT_pid_15;
Register<bit<32>, _>(1) GVT;

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;
    apply {
       if(hdr.ipv4.isValid()){
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});}
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    bit<32> aux_min;
 

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_0) Update_lvt_pid_0 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 0 ) value = hdr.gvt.value;
            rv = value;
        }
    };
    
    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_1) Update_lvt_pid_1 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 1 ) value = hdr.gvt.value;
            rv = value;
        }
    };    

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_2) Update_lvt_pid_2 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 2 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_3) Update_lvt_pid_3 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 3 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_4) Update_lvt_pid_4 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 4 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_5) Update_lvt_pid_5 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 5 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_6) Update_lvt_pid_6 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid ==6 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_7) Update_lvt_pid_7 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 7 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_8) Update_lvt_pid_8 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 8 ) value = hdr.gvt.value;
            rv = value;
        }
    };
    
    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_9) Update_lvt_pid_9 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 9 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_10) Update_lvt_pid_10 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 10 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_11) Update_lvt_pid_11 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 11 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_12) Update_lvt_pid_12 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 12 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_13) Update_lvt_pid_13 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 13 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_14) Update_lvt_pid_14 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 14 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_15) Update_lvt_pid_15 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 15 ) value = hdr.gvt.value;
            rv = value;
        }
    };


    
    RegisterAction<bit<32>, _, bit<32>>(GVT) Update_GVT = {
    void apply(inout bit<32> value, out bit<32> rv) {
            value = aux_min;
//            value = min(value, 5 );
            rv = value;
        }
    };
    
    
    action drop_() {
        ig_intr_dprsr_md.drop_ctl = 0;
    }
    action ipv4_forward(PortId_t port, mac_addr_t dst_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action gvt_forward(PortId_t port, mac_addr_t dst_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
    }


    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = { 
            ipv4_forward;
            drop_;
        }
        size = 1024;
        default_action = drop_();
    }

    table eth_forward {
        key = {
            hdr.ethernet.src_addr: exact;
        }
        actions = {
            gvt_forward; 
        }
        size = 1024;
    }

    apply {
	if(hdr.gvt.isValid()){
		ig_md.iterator_0  = Update_lvt_pid_0.execute(0);
		ig_md.iterator_1  = Update_lvt_pid_1.execute(0);
		aux_min = min(ig_md.iterator_0, ig_md.iterator_1);
                ig_md.iterator_1  = Update_lvt_pid_2.execute(0);
                aux_min = min(aux_min, ig_md.iterator_1);
                ig_md.iterator_1  = Update_lvt_pid_3.execute(0);
                aux_min = min(aux_min, ig_md.iterator_1);
                ig_md.iterator_1  = Update_lvt_pid_4.execute(0);
                aux_min = min(aux_min, ig_md.iterator_1);
                ig_md.iterator_1  = Update_lvt_pid_5.execute(0);
                aux_min = min(aux_min, ig_md.iterator_1);
                ig_md.iterator_1  = Update_lvt_pid_6.execute(0);
                aux_min = min(aux_min, ig_md.iterator_1);
                ig_md.gvt = Update_GVT.execute(0);
		hdr.gvt.value = ig_md.gvt;
                hdr.gvt.type = TYPE_DELIVER;
                eth_forward.apply();
                //ig_intr_tm_md.mcast_grp_a =  999;
	}
        if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
	}
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
