register int_latency_reg {
	width: 64; // lo for latency, while hi for delta
	instance_count: BUCKET_COUNT;
	attributes: signed; // two signed 32-bits
}

blackbox stateful_alu update_latency_matched_alu {
	reg: int_latency_reg;

	// for absolute primitive, we can use two comparison to fix it instead of recirculation
	condition_lo: (latency_hdr.latency - register_lo) <= THRESHOLD;
	condition_hi: (register_lo - latency_hdr.latency) <= THRESHOLD;

	update_lo_1_predicate: condition_lo and condition_hi;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo or not condition_hi;
	update_lo_2_value: latency_hdr.latency;

	// for ALU being unable to directly output a-b, we calculate a-b in alu_hi and output alu_hi
	update_hi_1_value: latency_hdr.latency - register_lo;

	output_value: alu_hi;
	output_dst: meta.latency_delta;
}

action update_latency_matched() {
#ifdef DEBUG
	update_latency_matched_alu.execute_stateful_alu(0);
#else
	update_latency_matched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

blackbox stateful_alu update_latency_unmatched_alu {
	reg: int_latency_reg;

	update_lo_1_value: latency_hdr.latency;

	update_hi_1_value: THRESHOLD_PLUS_ONE;
}

action update_latency_unmatched() {
#ifdef DEBUG
	update_latency_unmatched_alu.execute_stateful_alu(0);
#else
	update_latency_unmatched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
	modify_field(meta.latency_delta, THRESHOLD_PLUS_ONE); // exceed the threshold to embed complete state
}

@pragma stage 1
table update_latency_tbl {
	reads {
		udp_hdr.dstPort: exact;
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		update_latency_matched;
		update_latency_unmatched;
		nop;
	}
	default_action: nop();
	size: 32;
}
