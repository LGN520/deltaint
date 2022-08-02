/***********************/
/* Packet Header Types */
/***********************/

header_type ethernet_t {
	fields {
		dstAddr: 48;
		srcAddr: 48;
		etherType: 16;
	}
}

header_type ipv4_t {
	fields {
		version: 4;
		ihl: 4;
		diffserv: 8;
		totalLen: 16;
		identification: 16;
		flags: 3;
		fragOffset: 13;
		ttl: 8;
		protocol: 8;
		hdrChecksum: 16;
		srcAddr: 32;
		dstAddr: 32;
	}
}

header_type udp_t {
	fields {
		srcPort: 16;
		dstPort: 16;
		hdrlen: 16;
		checksum: 16;
	}
}

header_type int_t {
	fields {
		/* TODO: Your Custom Header Type */
		power_bit: 1;
		padding: 7;
	}
}

header_type power_t {
	fields {
		power: 8 (signed);
	}
}

header_type metadata_t {
	fields {
		/* TODO: Your Metadata */
		int_srcip_dstip_predicate: 4;
		int_srcport_dstport_predicate: 4;
		int_protocol_predicate: 4;
		latency: 8 (signed);
		curinput: 8 (signed);
		power_delta: 8 (signed);
		ismatch: 1;
	}
}

header ethernet_t ethernet_hdr;
header ipv4_t ipv4_hdr;
header udp_t udp_hdr;
header int_t int_hdr;
header power_t power_hdr;
metadata metadata_t meta;
