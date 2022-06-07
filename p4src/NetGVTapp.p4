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

const bit<3> RESUB = 3w1;


parser TofinoIngressParser(
        packet_in pkt,
        inout metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
        
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    
    state parse_resubmit {
        pkt.extract(ig_md.resub_hdr);
        transition accept;
    }

    
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
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
        ig_md.resub_hdr = {0, 0};
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
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

//Considering 3 chunks of size 5

Register<bit<32>, _>(1) LVT_chunk_0;
Register<bit<32>, _>(1) LVT_chunk_1;



//chunk 0 1
Register<bit<32>, _>(2) LVT_pid_0;
Register<bit<32>, _>(2) LVT_pid_1;
Register<bit<32>, _>(2) LVT_pid_2;
Register<bit<32>, _>(2) LVT_pid_3;
Register<bit<32>, _>(2) LVT_pid_4;

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
    
    Resubmit() resubmit;
    
    apply {

       if (ig_intr_dprsr_md.resubmit_type == RESUB) {
            resubmit.emit<resub_t>(ig_md.resub_hdr);
       }    
    
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


    bit<32> aux_min = 0;
 

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


    
    RegisterAction<bit<32>, _, bit<32>>(LVT_chunk_0) read_chunk_0 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };


    RegisterAction<bit<32>, _, bit<32>>(LVT_chunk_0) Update_chunk_0 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            value = aux_min;
            rv = value;
        }
    };
    
    RegisterAction<bit<32>, _, bit<32>>(LVT_chunk_1) read_chunk_1 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };


    RegisterAction<bit<32>, _, bit<32>>(LVT_chunk_1) Update_chunk_1 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            value = aux_min;
            rv = value;
        }
    };
    
     
    RegisterAction<bit<32>, _, bit<32>>(GVT) Update_GVT = {
    void apply(inout bit<32> value, out bit<32> rv) {
            value = aux_min;
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
		
		if(ig_intr_md.resubmit_flag == 1){
		        ig_md.iterator_1 = read_chunk_0.execute(0);
			ig_md.iterator_0 = read_chunk_1.execute(0);
			aux_min = min(ig_md.iterator_0, ig_md.iterator_1);	
                	ig_md.gvt = Update_GVT.execute(0);
		 	hdr.gvt.value = ig_md.gvt;
                	hdr.gvt.type = TYPE_DELIVER;
                	eth_forward.apply();
                	ig_intr_tm_md.mcast_grp_a =  1;
		}else{		
			//update the proper chunk
			ig_md.iterator_0  = Update_lvt_pid_0.execute( hdr.gvt.chunk);
			ig_md.iterator_1  = Update_lvt_pid_1.execute( hdr.gvt.chunk);
			aux_min = min(ig_md.iterator_0, ig_md.iterator_1);
			ig_md.iterator_1  = Update_lvt_pid_2.execute( hdr.gvt.chunk);
			aux_min = min(aux_min, ig_md.iterator_1);
			ig_md.iterator_1  = Update_lvt_pid_3.execute( hdr.gvt.chunk);
			aux_min = min(aux_min, ig_md.iterator_1);
			ig_md.iterator_1  = Update_lvt_pid_4.execute( hdr.gvt.chunk);
			aux_min = min(aux_min, ig_md.iterator_1);
			if(hdr.gvt.chunk == 0) ig_md.gvt = Update_chunk_0.execute(0);
			if(hdr.gvt.chunk == 1) ig_md.gvt = Update_chunk_1.execute(0);      
			ig_intr_dprsr_md.resubmit_type = 3w1; 
	        }

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

