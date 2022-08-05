/***********************/
/* Ingress Processing (Normal Operation) */
/***********************/

action nop() {}

// Stage 0

action ipv4_forward(port) {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
	add_to_field(ipv4_hdr.ttl, -1);

	modify_field(int_hdr.eport_bit, 1);
	modify_field(eport_hdr.eport, port);

	add_header(int_hdr);
	add_header(eport_hdr);
}

#ifdef DEBUG
counter ipv4_lpm_counter {
	type: packets_and_bytes;
	direct: ipv4_lpm;
}
#endif

@pragma stage 0
table ipv4_lpm {
	reads {
		ipv4_hdr.dstAddr: lpm;
	}
	actions {
		ipv4_forward;
		nop;
	}
	default_action: nop();
	size: 1;
}

// Stage 1

action set_igmeta(deviceid) {
	modify_field(int_hdr.deviceid_bit, 1);
	modify_field(deviceid_hdr.deviceid, deviceid);
	modify_field(int_hdr.iport_bit, 1);
	modify_field(iport_hdr.iport, ig_intr_md.ingress_port);
	modify_field(int_hdr.latency_bit, 1);
	modify_field(latency_hdr.latency, 0);
	
	add_header(iport_hdr);
	add_header(deviceid_hdr);
	add_header(latency_hdr);
	remove_header(latency_delta_hdr);
}

#ifdef DEBUG
counter set_igmeta_counter {
	type: packets_and_bytes;
	direct: set_igmeta_tbl;
}
#endif

@pragma stage 1
table set_igmeta_tbl {
	actions {
		set_igmeta;
	}
	default_action: set_igmeta(1);
	size: 1;	  
}
