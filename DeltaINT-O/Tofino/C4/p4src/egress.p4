/***********************/
/* Egress Processing */
/***********************/

// Stage 0

action set_egmeta() {
	modify_field(latency_hdr.latency, eg_intr_md.deq_timedelta);
	add_to_field(ipv4_hdr.ttl, -1);

	add_header(int_hdr);

	add_to_field(ipv4_hdr.totalLen, 1);
	add_to_field(udp_hdr.hdrlen, 1);
}

#ifdef DEBUG
counter set_egmeta_counter {
	type: packets_and_bytes;
	direct: set_egmeta_tbl;
}
#endif

@pragma stage 0
table set_egmeta_tbl {
	actions {
		set_egmeta;
	}
	default_action: set_egmeta();
	size: 1;
}

// Stage 2

action insert_latency() {
	modify_field(int_hdr.latency_bit, 1);

	add_header(latency_hdr);

	add_to_field(ipv4_hdr.totalLen, 4);
	add_to_field(udp_hdr.hdrlen, 4);
}

action omit_latency_delta() {
	modify_field(int_hdr.latency_bit, 0);

	remove_header(latency_hdr);
}

#ifdef DEBUG
counter latency_insert_counter {
	type: packets_and_bytes;
	direct: latency_insert_tbl;
}
#endif

@pragma stage 2
table latency_insert_tbl {
	reads {
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
		//meta.latency_delta: range; // if in [-1, 1] insert delta; otherwise, insert complete state (default action)
		meta.latency_delta: exact; // insert delta only if delta in [-1, 1]
	}
	actions {
		insert_latency;
		omit_latency_delta;
	}
	default_action: insert_latency();
	size: 4;
}
