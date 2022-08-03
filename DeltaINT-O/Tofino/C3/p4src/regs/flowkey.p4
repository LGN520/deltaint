// 192 KB < 256 KB in total

register int_srcip_dstip_reg {
	width: 64; // low: srcip; high: dstip
	instance_count: BUCKET_COUNT;
}

blackbox stateful_alu update_srcip_dstip_alu {
	reg: int_srcip_dstip_reg;

	condition_lo: ipv4_hdr.srcAddr == register_lo;
	condition_hi: ipv4_hdr.dstAddr == register_hi;
	
	update_lo_1_predicate: condition_lo and condition_hi;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo or not condition_hi;
	update_lo_2_value: ipv4_hdr.srcAddr;

	update_hi_1_predicate: condition_lo and condition_hi;
	update_hi_1_value: register_hi;
	update_hi_2_predicate: not condition_lo or not condition_hi;
	update_hi_2_value: ipv4_hdr.dstAddr;

	output_value: predicate; // false: 1/2/4; true: 8
	output_dst: meta.int_srcip_dstip_predicate;
}

action update_srcip_dstip() {
#ifdef DEBUG
	update_srcip_dstip_alu.execute_stateful_alu(0);
#else
	update_srcip_dstip_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

@pragma stage 0
table update_srcip_dstip_tbl {
	reads {
		udp_hdr.dstPort: exact;
	}
	actions {
		update_srcip_dstip;
		nop;
	}
	default_action: nop();
	size: 1;
}

register int_srcport_dstport_reg {
	width: 32; // low: srcport; high: dstport
	instance_count: BUCKET_COUNT;
}

blackbox stateful_alu update_srcport_dstport_alu {
	reg: int_srcport_dstport_reg;

	condition_lo: udp_hdr.srcPort == register_lo;
	condition_hi: udp_hdr.dstPort == register_hi;
	
	update_lo_1_predicate: condition_lo and condition_hi;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo or not condition_hi;
	update_lo_2_value: udp_hdr.srcPort;

	update_hi_1_predicate: condition_lo and condition_hi;
	update_hi_1_value: register_hi;
	update_hi_2_predicate: not condition_lo or not condition_hi;
	update_hi_2_value: udp_hdr.dstPort;

	output_value: predicate; // false: 1/2/4; true: 8
	output_dst: meta.int_srcport_dstport_predicate;
}

action update_srcport_dstport() {
#ifdef DEBUG
	update_srcport_dstport_alu.execute_stateful_alu(0);
#else
	update_srcport_dstport_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

@pragma stage 0
table update_srcport_dstport_tbl {
	reads {
		udp_hdr.dstPort: exact;
	}
	actions {
		update_srcport_dstport;
		nop;
	}
	default_action: nop();
	size: 1;
}

register int_protocol_reg {
	width: 8;
	instance_count: BUCKET_COUNT;
}

blackbox stateful_alu update_protocol_alu {
	reg: int_protocol_reg;

	condition_lo: ipv4_hdr.protocol == register_lo;
	
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: register_lo;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: ipv4_hdr.protocol;

	output_value: predicate; // false: 1; true: 2
	output_dst: meta.int_protocol_predicate;
}

action update_protocol() {
#ifdef DEBUG
	update_protocol_alu.execute_stateful_alu(0);
#else
	update_protocol_alu.execute_stateful_alu_from_hash(hash_field_calc);
#endif
}

@pragma stage 0
table update_protocol_tbl {
	reads {
		udp_hdr.dstPort: exact;
	}
	actions {
		update_protocol;
		nop;
	}
	default_action: nop();
	size: 1;
}
