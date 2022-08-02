/***********************/
/* Egress Processing */
/***********************/

// Stage 0

action set_egmeta() {
	modify_field(meta.latency, eg_intr_md.deq_timedelta); // not find link utilization in Tofino; use latency which does NOT affect hardware resource usage result
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

action set_output() {
	max(power_hdr.power, meta.curinput, meta.latency);
}

@pragma stage 2
table set_output_tbl {
	reads {
		udp_hdr.dstPort: exact;
	}
	actions {
		set_output;
		nop;
	}
	default_action: nop();
	size: 1;
}

// Stage 4

action insert_power() {
	modify_field(int_hdr.power_bit, 1);

	add_header(power_hdr);
}

action omit_power_delta() {
	modify_field(int_hdr.power_bit, 0);

	remove_header(power_hdr);
}

#ifdef DEBUG
counter power_insert_counter {
	type: packets_and_bytes;
	direct: power_insert_tbl;
}
#endif

@pragma stage 4
table power_insert_tbl {
	reads {
		meta.ismatch: exact;
		//meta.power_delta: range; // if in [-1, 1] insert delta; otherwise, insert complete state (default action)
		meta.power_delta: exact; // insert delta only if delta in [-1, 1]
	}
	actions {
		insert_power;
		omit_power_delta;
	}
	default_action: insert_power();
	size: 4;
}
