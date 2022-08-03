/***********************/
/* Parser */
/***********************/

parser start {
	return parse_ethernet;
}

parser parse_ethernet {
	extract(ethernet_hdr);
	return select(ethernet_hdr.etherType) {
		ETHERTYPE_IPV4: parse_ipv4;
		default: ingress;
	}
}

parser parse_ipv4 {
	extract(ipv4_hdr);
	return select(ipv4_hdr.protocol) {
		PROTOTYPE_UDP: parse_udp;
		default: ingress;
	}
}

parser parse_udp {
	extract(udp_hdr);
	return select(udp_hdr.dstPort) {
		DINT_DSTPORT: parse_int_prepare;
		default: ingress;
	}
}

parser parse_int_prepare {
	return select(ipv4_hdr.ttl) {
		INGRESS_TTL_MASK mask 0x01: ingress;
		EGRESS_TTL_MASK mask 0x01: parse_int;
		default: ingress;
	}
}

parser parse_int {
	extract(int_hdr);
	return select(int_hdr.latency_bit) {
		1: parse_latency;
		default: parse_latency_delta;
	}
}

parser parse_latency {
	extract(latency_hdr);
	return ingress;
}

parser parse_latency_delta {
	extract(latency_delta_hdr);
	return ingress;
}

/***********************/
/* Hash Fields */
/***********************/

field_list hash_fields {
	ipv4_hdr.srcAddr;
	ipv4_hdr.dstAddr;
	udp_hdr.srcPort;
	udp_hdr.dstPort;
	ipv4_hdr.protocol;
}

field_list_calculation hash_field_calc {
	input {
		hash_fields;
	}
#ifdef BMV2TOFINO
	algorithm: crc32;
#else
	algorithm: random;
#endif
	output_width: 13;
}
