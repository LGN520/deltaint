/***********************/
/* Egress Processing */
/***********************/

// Stage 0

action set_egmeta(deviceid) {
	modify_field(deviceid_hdr.deviceid, deviceid);
}

#ifdef DEBUG
counter set_igmeta_counter {
	type: packets_and_bytes;
	direct: set_igmeta_tbl;
}
#endif

@pragma stage 0
table set_egmeta_tbl {
	reads {
		udp_hdr.dstPort: exact;
	}
	actions {
		set_egmeta;
		nop;
	}
	default_action: nop();
	size: 1;	  
}

// Stage 1

action set_deviceid_bit() {
	add_to_field(ipv4_hdr.ttl, -1);

	modify_field(int_hdr.deviceid_bit, 1);
	add_header(deviceid_hdr);

	add_to_field(ipv4_hdr.totalLen, 1);
	add_to_field(udp_hdr.hdrlen, 1);
}

action reset_deviceid_bit() {
	add_to_field(ipv4_hdr.ttl, -1);

	modify_field(int_hdr.deviceid_bit, 0);
	remove_header(deviceid_hdr);
}

@pragma stage 1
table set_deviceid_bit_tbl {
	reads {
		udp_hdr.dstPort: exact;
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		set_deviceid_bit;
		reset_deviceid_bit;
		nop;
	}
	default_action: nop();
	size: 32;
}

action set_deviceid() {
	add_to_field(ipv4_hdr.ttl, -1);

	add_header(deviceid_hdr);

	add_to_field(ipv4_hdr.totalLen, 1);
	add_to_field(udp_hdr.hdrlen, 1);
}

action reset_deviceid() {
	add_to_field(ipv4_hdr.ttl, -1);

	remove_header(deviceid_hdr);
}

@pragma stage 1
table set_deviceid_tbl {
	reads {
		udp_hdr.dstPort: exact;
		int_hdr.deviceid_bit: exact;
	}
	actions {
		set_deviceid;
		reset_deviceid;
		nop;
	}
	default_action: nop();
	size: 2;
}
