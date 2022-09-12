const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_GVT = 0x600;
const bit<32> TYPE_PROP = 0x1919;
const bit<32> TYPE_DEL = 0x1313;

const bit<32> TYPE_REQ = 0x1515;
const bit<32> TYPE_PREPARE = 0x3333;
const bit<32> TYPE_PREPAREOK = 0x4444;


#define TOTAL_NUMBER_OF_PROCESSES 3
#define INFINITE 1000000
#define MAJORITY 2

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*GVT definitions*/
typedef bit<32> lpid_t;
typedef bit<32> value_t;
//typedef bit<32> round_t;  

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header gvt_t{
    bit<32> type;
    value_t value;
    lpid_t  pid;
    bit<32> round; 
}

struct metadata {
    bit<32> readedValue;
    bit<32> currentGVT;
    bit<32> numProposals;
    bit<32> minLVT;
    bit<32> iterator;
    bit<32> numPrepareOks;
    bit<32> currentRound;
    egressSpec_t out_aux;
}

struct headers {
    ethernet_t     ethernet;
    ipv4_t             ipv4;
    gvt_t               gvt;
}
