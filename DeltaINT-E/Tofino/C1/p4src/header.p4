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
		deviceid_bit: 1;
		iport_bit: 1;
		eport_bit: 1;
		latency_bit: 1;
		padding: 4;
	}
}

header_type deviceid_t {
	fields {
		deviceid: 8;
	}
}

header_type iport_t {
	fields {
		iport: 8;
	}
}

header_type eport_t {
	fields {
		eport: 8;
	}
}

header_type latency_t {
	fields {
		latency: 32 (signed);
	}
}

header_type latency_delta_t {
	fields {
		latency_delta: 2; // encoded negligible latency delta
		padding: 6;
	}
}

header_type metadata_t {
	fields {
		/* TODO: Your Metadata */
		int_srcip_dstip_predicate: 4;
		int_srcport_dstport_predicate: 4;
		int_protocol_predicate: 4;
		int_deviceid_iport_predicate: 4;
		int_eport_predicate: 4;
		latency_delta: 32 (signed); // original latency delta
	}
}

header ethernet_t ethernet_hdr;
header ipv4_t ipv4_hdr;
header udp_t udp_hdr;
header int_t int_hdr;
header deviceid_t deviceid_hdr;
header iport_t iport_hdr;
header eport_t eport_hdr;
header latency_t latency_hdr;
header latency_delta_t latency_delta_hdr;
metadata metadata_t meta;
