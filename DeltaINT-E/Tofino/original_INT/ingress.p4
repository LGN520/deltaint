// Stage 0

action ipv4_forward(port) {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
	add_to_field(ipv4.ttl, -1);

    add_header(int_egress_port_id_header);
    modify_field(int_egress_port_id_header.egress_port_id, port);
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
		ipv4.dstAddr: lpm;
	}
	actions {
		ipv4_forward;
		nop;
	}
	default_action: nop();
	size: 1;
}

// Stage 1

action int_set_header_0(switch_id) {
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, switch_id);
}

@pragma stage 1
table int_set_header_0_tbl {
	actions {
		int_set_header_0;
	}
	default_action: int_set_header_0(1);
	size: 1;
}

action int_set_header_1() {
    add_header(int_ingress_port_id_header);
    modify_field(
        int_ingress_port_id_header.ingress_port_id, ig_intr_md.ingress_port);
}

@pragma stage 1
table int_set_header_1_tbl {
	actions {
		int_set_header_1;
	}
	default_action: int_set_header_1();
	size: 1;
}

action int_set_intl45_head_header() {
	add_header(int_hop_latency_header);
	modify_field(int_hop_latency_header.hop_latency, 0);

	add_to_field(intl45_head_header.len, 1);

	add_to_field(ipv4.totalLen, 3);
	add_to_field(udp.length_, 3);
}

@pragma stage 1
table int_set_intl45_head_header_tbl {
	actions {
		int_set_intl45_head_header;
	}
	default_action: int_set_intl45_head_header();
	size: 1;
}
