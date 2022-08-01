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

	output_value: predicate; // for deviceid, false: 5/9, true: 6/10; for iport, false: 5/6, true: 9/10
	output_dst: meta.int_deviceid_iport_predicate;
}

blackbox stateful_alu update_deviceid_iport_unmatched_alu {
	reg: int_deviceid_iport_reg;

	update_lo_1_value: deviceid_hdr.deviceid;
	update_lo_2_value: iport_hdr.iport;
}

action update_deviceid_iport_matched() {
	update_deviceid_iport_matched_alu.execute_stateful_alu_from_hash(hash_field_calc);
}

action update_deviceid_iport_unmatched() {
	update_deviceid_iport_unmatched_alu.execute_stateful_alu_from_hash(hash_field_calc);
	modify_field(meta.int_deviceid_iport_predicate, 5); // false for both deviceid and iport
}

@pragma stage 1
table update_deviceid_iport_tbl {
	reads {
		udp_hdr.dstPort: exact;
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
