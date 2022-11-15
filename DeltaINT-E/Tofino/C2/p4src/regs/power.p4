register int_previnput_reg {
	width: 8;
	instance_count: BUCKET_COUNT;
	attributes: signed;
}

blackbox stateful_alu update_previnput_matched_alu {
	reg: int_previnput_reg;

	condition_lo: int_hdr.power_bit == 1;

	update_lo_1_predicate: condition_lo;
	update_lo_1_value: power_hdr.power;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: register_lo;

	output_value: alu_lo;
	output_dst: meta.curinput;
}

action update_previnput_matched() {
#ifdef DEBUG
	update_previnput_matched_alu.execute_stateful_alu(0);
#else
	update_previnput_matched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

// NOTE: hash collision is extremely rare
blackbox stateful_alu update_previnput_unmatched_alu {
	reg: int_previnput_reg;

	condition_lo: int_hdr.power_bit == 1;

	update_lo_1_predicate: condition_lo;
	update_lo_1_value: power_hdr.power;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: 0;

	output_value: alu_lo;
	output_dst: meta.curinput;
}

action update_previnput_unmatched() {
#ifdef DEBUG
	update_previnput_unmatched_alu.execute_stateful_alu(0);
#else
	update_previnput_unmatched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

@pragma stage 2
table update_previnput_tbl {
	reads {
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		update_previnput_matched;
		update_previnput_unmatched;
		nop;
	}
	default_action: nop();
	size: 32;
}

register int_prevoutput_reg {
	width: 16; // lo for power, while hi for power delta
	instance_count: BUCKET_COUNT;
	attributes: signed; // two signed 8-bits
}

blackbox stateful_alu update_prevoutput_matched_alu {
	reg: int_prevoutput_reg;

	condition_lo: (power_hdr.power - register_lo) <= THRESHOLD;
	condition_hi: (register_lo - power_hdr.power) <= THRESHOLD;

	update_lo_1_predicate: condition_lo and condition_hi;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo or not condition_hi;
	update_lo_2_value: power_hdr.power;

	update_hi_1_value: power_hdr.power - register_lo;

	output_value: alu_hi; 
	output_dst: meta.power_delta;
}

action update_prevoutput_matched() {
#ifdef DEBUG
	update_prevoutput_matched_alu.execute_stateful_alu(0);
#else
	update_prevoutput_matched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

blackbox stateful_alu update_prevoutput_unmatched_alu {
	reg: int_prevoutput_reg;

	update_lo_1_value: power_hdr.power;
}

action update_prevoutput_unmatched() {
#ifdef DEBUG
	update_prevoutput_unmatched_alu.execute_stateful_alu(0);
#else
	update_prevoutput_unmatched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
	modify_field(meta.power_delta, THRESHOLD_PLUS_ONE);
}

@pragma stage 4
table update_prevoutput_tbl {
	reads {
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		update_prevoutput_matched;
		update_prevoutput_unmatched;
		nop;
	}
	default_action: nop();
	size: 32;
}
