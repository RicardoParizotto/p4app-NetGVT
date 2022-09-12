/* -*- P4_16 -*- */

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) Intel Corporation
 * SPDX-License-Identifier: CC-BY-ND-4.0
 */



#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;


typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const ether_type_t ETHERTYPE_GVT = 16w0x8666;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_GVT = 10;

const bit<32> TYPE_PROPOSAL = 1;
const bit<32> TYPE_DELIVER = 0;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}


//netgvt header
header gvt_h {
    bit<32> type;
    bit<32> pid;
    bit<32> value;
    bit<32> chunk;
}

//this one is for resubmitions
header resub_t {
    bit<32> iterator;
    bit<32> min_value;
//    bit<32> last_it;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    gvt_h gvt;
}

struct metadata_t {
    bit<32> iterator_0;
    bit<32> iterator_1;
    bit<32> gvt;   
    resub_t resub_hdr;        
}


struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _HEADERS_ */
