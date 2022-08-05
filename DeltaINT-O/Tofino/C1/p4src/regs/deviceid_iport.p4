register int_deviceid_iport_reg {
	width: 16;
	instance_count: BUCKET_COUNT;
}

blackbox stateful_alu update_deviceid_iport_matched_alu {
	reg: int_deviceid_iport_reg;

	condition_lo: register_lo == deviceid_hdr.deviceid;
	condition_hi: register_hi == iport_hdr.iport; 

	update_lo_1_predicate: condition_lo;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: deviceid_hdr.deviceid;

	update_hi_1_predicate: condition_hi;
	update_hi_1_value: register_hi;
	update_hi_2_predicate: not condition_hi;
	update_hi_2_value: iport_hdr.iport; 

	output_value: predicate; // for deviceid, false: 1/4, true: 2/8; for iport, false: 1/2, true: 4/8
	output_dst: meta.int_deviceid_iport_predicate;
}

blackbox stateful_alu update_deviceid_iport_unmatched_alu {
	reg: int_deviceid_iport_reg;

	update_lo_1_value: deviceid_hdr.deviceid;

	update_hi_1_value: iport_hdr.iport;
}

action update_deviceid_iport_matched() {
#ifdef DEBUG
	update_deviceid_iport_matched_alu.execute_stateful_alu(0);
#else
	update_deviceid_iport_matched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

action update_deviceid_iport_unmatched() {
#ifdef DEBUG
	update_deviceid_iport_unmatched_alu.execute_stateful_alu(0);
#else
	update_deviceid_iport_unmatched_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
	modify_field(meta.int_deviceid_iport_predicate, 1); // false for both deviceid and iport
}

@pragma stage 1
table update_deviceid_iport_tbl {
	reads {
		meta.int_srcip_dstip_predicate: exact;
		meta.int_srcport_dstport_predicate: exact;
		meta.int_protocol_predicate: exact;
	}
	actions {
		update_deviceid_iport_matched;
		update_deviceid_iport_unmatched;
		nop;
	}
	default_action: nop();
	size: 32;
}
