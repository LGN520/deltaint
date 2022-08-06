action int_set_header_2() {
    modify_field(int_hop_latency_header.hop_latency, eg_intr_md.deq_timedelta);

	// hop latency
	add_to_field(ipv4.totalLen, 1);
	add_to_field(udp.length_, 1);
}

@pragma stage 0
table int_set_header_2_tbl {
	actions {
		int_set_header_2;
	}
	default_action: int_set_header_2();
	size: 1;
}
