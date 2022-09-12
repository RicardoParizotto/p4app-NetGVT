parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_GVT: parse_gvt;
            default: accept;
        }
    }

    state parse_gvt {
        packet.extract(hdr.gvt);
	transition accept;	
    }
     
    /*
    state parse_viewchange{
        packet.extract(hdr.viewchange.next){
	   transition select(hdr.viewchange.last.proto_id){
	       TYPE_DOCHANGE: parse_viewchange;	
	       default:accept;
	   }
        }
    }
    */

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.gvt);
        packet.emit(hdr.viewchange);
        packet.emit(hdr.ipv4);
    }
}
