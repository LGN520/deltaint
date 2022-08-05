register int_eport_reg {
	width: 8;
	instance_count: BUCKET_COUNT;
}

blackbox stateful_alu update_eport_matched_alu {
	reg: int_eport_reg;

	condition_lo: register_lo == eport_hdr.eport; 

	update_lo_1_predicate: condition_lo;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: eport_hdr.eport; 

	output_value: predicate;
	output_dst: meta.int_eport_predicate; // false: 1, true: 2
}

action update_eport_matched() {
#ifdef DEBUG
	update_eport_matched_alu.execute_stateful_alu(0);
#else
	update_eport_matched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

blackbox stateful_alu update_eport_unmatched_alu {
	reg: int_eport_reg;

	update_lo_1_value: eport_hdr.eport;
}

action update_eport_unmatched() {
#ifdef DEBUG
	update_eport_unmatched_alu.execute_stateful_alu(0);
#else
	update_eport_unmatched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
	modify_field(meta.int_eport_predicate, 1);
}

@pragma stage 1
table update_eport_tbl {
	reads {
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		update_eport_matched;
		update_eport_unmatched;
		nop;
	}
	default_action: nop();
	size: 32;
}
