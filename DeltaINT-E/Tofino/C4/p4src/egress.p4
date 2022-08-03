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

action ismatch() {
	modify_field(meta.ismatch, 1);
}

action notmatch() {
	modify_field(meta.ismatch, 0);
}

#ifdef DEBUG
counter ismatch_counter {
	type: packets_and_bytes;
	direct: ismatch_tbl;
}
#endif

@pragma stage 1
table ismatch_tbl {
	reads {
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		ismatch;
		notmatch;
	}
	default_action: notmatch();
	size: 1;
}

// Stage 2

action insert_latency() {
	modify_field(int_hdr.latency_bit, 1);

	add_header(latency_hdr);
	remove_header(latency_delta_hdr);

	add_to_field(ipv4_hdr.totalLen, 4);
	add_to_field(udp_hdr.hdrlen, 4);
}

action insert_latency_delta(encoded_delta) {
	modify_field(int_hdr.latency_bit, 0);
	modify_field(latency_delta_hdr.latency_delta, encoded_delta);

	remove_header(latency_hdr);
	add_header(latency_delta_hdr);

	add_to_field(ipv4_hdr.totalLen, 1);
	add_to_field(udp_hdr.hdrlen, 1);
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
		meta.ismatch: exact;
		//meta.latency_delta: range; // if in [-1, 1] insert delta; otherwise, insert complete state (default action)
		meta.latency_delta: exact; // insert delta only if delta in [-1, 1]
	}
	actions {
		insert_latency;
		insert_latency_delta;
	}
	default_action: insert_latency();
	size: 4;
}
