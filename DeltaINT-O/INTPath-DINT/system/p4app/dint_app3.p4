#include <core.p4>
#include "v1model.p4"

#include "dint_header3.p4"
#include "dint_parser.p4"

#define COUNTER_SIZE 32w16

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    counter(COUNTER_SIZE,CounterType.packets) egress_counter;

    @name("_drop")
    action _drop() {
        mark_to_drop(standard_metadata);
    }

	// 340 KB space: 104-bit flowkey, 8-bit deviceno, 8-bit iport, 8-bit eport, 32-bit timedelta
	register<bit<128>>(17408) dint_register;
	register<bit<32>>(17408) timedelta_register;

	// 340 KB space: 104-bit flowkey, 8-bit deviceno, 8-bit iport, 8-bit eport, 32-bit timedelta
	register<bit<128>>(17408) dint_register2;
	register<bit<32>>(17408) timedelta_register2;

	// 340 KB space: 104-bit flowkey, 8-bit deviceno, 8-bit iport, 8-bit eport, 32-bit timedelta
	register<bit<128>>(17408) dint_register3;
	register<bit<32>>(17408) timedelta_register3;

	@name("dint_hash")
	action dint_hash() {
		hash(meta.dint_metadata.index, HashAlgorithm.crc16, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol}, 32w17408);
	}
	@name("dint_hash_tbl")
	table dint_hash_tbl {
		actions = {
			dint_hash;
		}
		key = {}
		size = 1024;
		default_action = dint_hash();
	}

	@name("dint_hash2")
	action dint_hash2() {
		hash(meta.dint_metadata.index2, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol}, 32w17408);
	}
	@name("dint_hash2_tbl")
	table dint_hash2_tbl {
		actions = {
			dint_hash2;
		}
		key = {}
		size = 1024;
		default_action = dint_hash2();
	}

	@name("dint_hash3")
	action dint_hash3() {
		hash(meta.dint_metadata.index3, HashAlgorithm.csum16, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol}, 32w17408);
	}
	@name("dint_hash3_tbl")
	table dint_hash3_tbl {
		actions = {
			dint_hash3;
		}
		key = {}
		size = 1024;
		default_action = dint_hash3();
	}

	@name("read_register")
	action read_register() {
		dint_register.read(meta.dint_metadata.register_value, meta.dint_metadata.index);
		timedelta_register.read(meta.dint_metadata.prev_timedelta, meta.dint_metadata.index);
	}
	@name("read_register_tbl")
	table read_register_tbl {
		actions = {
			read_register;
		}
		key = {}
		size = 1024;
		default_action = read_register();
	}

	@name("read_register2")
	action read_register2() {
		dint_register2.read(meta.dint_metadata.register_value2, meta.dint_metadata.index2);
		timedelta_register2.read(meta.dint_metadata.prev_timedelta2, meta.dint_metadata.index2);
	}
	@name("read_register2_tbl")
	table read_register2_tbl {
		actions = {
			read_register2;
		}
		key = {}
		size = 1024;
		default_action = read_register2();
	}

	@name("read_register3")
	action read_register3() {
		dint_register3.read(meta.dint_metadata.register_value3, meta.dint_metadata.index3);
		timedelta_register3.read(meta.dint_metadata.prev_timedelta3, meta.dint_metadata.index3);
	}
	@name("read_register3_tbl")
	table read_register3_tbl {
		actions = {
			read_register3;
		}
		key = {}
		size = 1024;
		default_action = read_register3();
	}

	@name("parse_register")
	action parse_register() {
		meta.dint_metadata.srcAddr = (bit<32>)(meta.dint_metadata.register_value >> 96);
		meta.dint_metadata.dstAddr = (bit<32>)(meta.dint_metadata.register_value >> 64);
		meta.dint_metadata.srcPort = (bit<16>)(meta.dint_metadata.register_value >> 48);
		meta.dint_metadata.dstPort = (bit<16>)(meta.dint_metadata.register_value >> 32);
		meta.dint_metadata.protocol = (bit<8>)(meta.dint_metadata.register_value >> 24);
		meta.dint_metadata.prev_deviceno = (bit<8>)(meta.dint_metadata.register_value >> 16);
		meta.dint_metadata.prev_iport = (bit<8>)(meta.dint_metadata.register_value >> 8);
		meta.dint_metadata.prev_eport = (bit<8>)(meta.dint_metadata.register_value);
	}
	@name("parse_register_tbl")
	table parse_register_tbl {
		actions = {
			parse_register;
		}
		key = {}
		size = 1024;
		default_action = parse_register();
	}

	@name("parse_register2")
	action parse_register2() {
		meta.dint_metadata.srcAddr2 = (bit<32>)(meta.dint_metadata.register_value2 >> 96);
		meta.dint_metadata.dstAddr2 = (bit<32>)(meta.dint_metadata.register_value2 >> 64);
		meta.dint_metadata.srcPort2 = (bit<16>)(meta.dint_metadata.register_value2 >> 48);
		meta.dint_metadata.dstPort2 = (bit<16>)(meta.dint_metadata.register_value2 >> 32);
		meta.dint_metadata.protocol2 = (bit<8>)(meta.dint_metadata.register_value2 >> 24);
		meta.dint_metadata.prev_deviceno2 = (bit<8>)(meta.dint_metadata.register_value2 >> 16);
		meta.dint_metadata.prev_iport2 = (bit<8>)(meta.dint_metadata.register_value2 >> 8);
		meta.dint_metadata.prev_eport2 = (bit<8>)(meta.dint_metadata.register_value2);
	}
	@name("parse_register2_tbl")
	table parse_register2_tbl {
		actions = {
			parse_register2;
		}
		key = {}
		size = 1024;
		default_action = parse_register2();
	}

	@name("parse_register3")
	action parse_register3() {
		meta.dint_metadata.srcAddr3 = (bit<32>)(meta.dint_metadata.register_value3 >> 96);
		meta.dint_metadata.dstAddr3 = (bit<32>)(meta.dint_metadata.register_value3 >> 64);
		meta.dint_metadata.srcPort3 = (bit<16>)(meta.dint_metadata.register_value3 >> 48);
		meta.dint_metadata.dstPort3 = (bit<16>)(meta.dint_metadata.register_value3 >> 32);
		meta.dint_metadata.protocol3 = (bit<8>)(meta.dint_metadata.register_value3 >> 24);
		meta.dint_metadata.prev_deviceno3 = (bit<8>)(meta.dint_metadata.register_value3 >> 16);
		meta.dint_metadata.prev_iport3 = (bit<8>)(meta.dint_metadata.register_value3 >> 8);
		meta.dint_metadata.prev_eport3 = (bit<8>)(meta.dint_metadata.register_value3);
	}
	@name("parse_register3_tbl")
	table parse_register3_tbl {
		actions = {
			parse_register3;
		}
		key = {}
		size = 1024;
		default_action = parse_register3();
	}

	@name("delta_calc")
	action delta_calc() {
		hdr.intbitmap.setValid();
		if (meta.dint_metadata.prev_deviceno == meta.int_metadata.device_no) {
			hdr.intbitmap.device_bit = 0;
			meta.dint_metadata.output_deviceno = meta.dint_metadata.prev_deviceno;
		}
		else {
			hdr.intbitmap.device_bit = 1;
			meta.dint_metadata.output_deviceno = meta.int_metadata.device_no;
		}
		if (meta.dint_metadata.prev_iport == (bit<8>)(standard_metadata.ingress_port)) {
			hdr.intbitmap.iport_bit = 0;
			meta.dint_metadata.output_iport = meta.dint_metadata.prev_iport;
		}
		else {
			hdr.intbitmap.iport_bit = 1;
			meta.dint_metadata.output_iport = (bit<8>)(standard_metadata.ingress_port);
		}
		if (meta.dint_metadata.prev_eport == (bit<8>)(standard_metadata.egress_port)) {
			hdr.intbitmap.eport_bit = 0;
			meta.dint_metadata.output_eport = meta.dint_metadata.prev_eport;
		}
		else {
			hdr.intbitmap.eport_bit = 1;
			meta.dint_metadata.output_eport = (bit<8>)(standard_metadata.egress_port);
		}
		if ((meta.dint_metadata.prev_timedelta >= standard_metadata.deq_timedelta) && ((meta.dint_metadata.prev_timedelta - standard_metadata.deq_timedelta) <= 10) || \
				(meta.dint_metadata.prev_timedelta < standard_metadata.deq_timedelta) && ((standard_metadata.deq_timedelta - meta.dint_metadata.prev_timedelta) <= 10)) {
			hdr.intbitmap.timedelta_bit = 0;
			meta.dint_metadata.output_timedelta = meta.dint_metadata.prev_timedelta;
		}
		else {
			hdr.intbitmap.timedelta_bit = 1;
			meta.dint_metadata.output_timedelta = standard_metadata.deq_timedelta;
		}
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.udp.hdrChecksum = 16w0;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	@name("delta_calc_tbl")
	table delta_calc_tbl {
		actions = {
			delta_calc;
		}
		key = {}
		size = 1024;
		default_action = delta_calc();
	}

	@name("delta_calc2")
	action delta_calc2() {
		hdr.intbitmap.setValid();
		if (meta.dint_metadata.prev_deviceno2 == meta.int_metadata.device_no) {
			hdr.intbitmap.device_bit = 0;
			meta.dint_metadata.output_deviceno = meta.dint_metadata.prev_deviceno2;
		}
		else {
			hdr.intbitmap.device_bit = 1;
			meta.dint_metadata.output_deviceno = meta.int_metadata.device_no;
		}
		if (meta.dint_metadata.prev_iport2 == (bit<8>)(standard_metadata.ingress_port)) {
			hdr.intbitmap.iport_bit = 0;
			meta.dint_metadata.output_iport = meta.dint_metadata.prev_iport2;
		}
		else {
			hdr.intbitmap.iport_bit = 1;
			meta.dint_metadata.output_iport = (bit<8>)(standard_metadata.ingress_port);
		}
		if (meta.dint_metadata.prev_eport2 == (bit<8>)(standard_metadata.egress_port)) {
			hdr.intbitmap.eport_bit = 0;
			meta.dint_metadata.output_eport = meta.dint_metadata.prev_eport2;
		}
		else {
			hdr.intbitmap.eport_bit = 1;
			meta.dint_metadata.output_eport = (bit<8>)(standard_metadata.egress_port);
		}
		if ((meta.dint_metadata.prev_timedelta2 >= standard_metadata.deq_timedelta) && ((meta.dint_metadata.prev_timedelta2 - standard_metadata.deq_timedelta) <= 10) || \
				(meta.dint_metadata.prev_timedelta2 < standard_metadata.deq_timedelta) && ((standard_metadata.deq_timedelta - meta.dint_metadata.prev_timedelta2) <= 10)) {
			hdr.intbitmap.timedelta_bit = 0;
			meta.dint_metadata.output_timedelta = meta.dint_metadata.prev_timedelta2;
		}
		else {
			hdr.intbitmap.timedelta_bit = 1;
			meta.dint_metadata.output_timedelta = standard_metadata.deq_timedelta;
		}
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.udp.hdrChecksum = 16w0;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	@name("delta_calc2_tbl")
	table delta_calc2_tbl {
		actions = {
			delta_calc2;
		}
		key = {}
		size = 1024;
		default_action = delta_calc2();
	}

	@name("delta_calc3")
	action delta_calc3() {
		hdr.intbitmap.setValid();
		if (meta.dint_metadata.prev_deviceno3 == meta.int_metadata.device_no) {
			hdr.intbitmap.device_bit = 0;
			meta.dint_metadata.output_deviceno = meta.dint_metadata.prev_deviceno3;
		}
		else {
			hdr.intbitmap.device_bit = 1;
			meta.dint_metadata.output_deviceno = meta.int_metadata.device_no;
		}
		if (meta.dint_metadata.prev_iport3 == (bit<8>)(standard_metadata.ingress_port)) {
			hdr.intbitmap.iport_bit = 0;
			meta.dint_metadata.output_iport = meta.dint_metadata.prev_iport3;
		}
		else {
			hdr.intbitmap.iport_bit = 1;
			meta.dint_metadata.output_iport = (bit<8>)(standard_metadata.ingress_port);
		}
		if (meta.dint_metadata.prev_eport3 == (bit<8>)(standard_metadata.egress_port)) {
			hdr.intbitmap.eport_bit = 0;
			meta.dint_metadata.output_eport = meta.dint_metadata.prev_eport3;
		}
		else {
			hdr.intbitmap.eport_bit = 1;
			meta.dint_metadata.output_eport = (bit<8>)(standard_metadata.egress_port);
		}
		if ((meta.dint_metadata.prev_timedelta3 >= standard_metadata.deq_timedelta) && ((meta.dint_metadata.prev_timedelta3 - standard_metadata.deq_timedelta) <= 10) || \
				(meta.dint_metadata.prev_timedelta3 < standard_metadata.deq_timedelta) && ((standard_metadata.deq_timedelta - meta.dint_metadata.prev_timedelta3) <= 10)) {
			hdr.intbitmap.timedelta_bit = 0;
			meta.dint_metadata.output_timedelta = meta.dint_metadata.prev_timedelta3;
		}
		else {
			hdr.intbitmap.timedelta_bit = 1;
			meta.dint_metadata.output_timedelta = standard_metadata.deq_timedelta;
		}
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.udp.hdrChecksum = 16w0;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	@name("delta_calc3_tbl")
	table delta_calc3_tbl {
		actions = {
			delta_calc3;
		}
		key = {}
		size = 1024;
		default_action = delta_calc3();
	}

	action set_bitmap() {
		hdr.intbitmap.setValid();
		hdr.intbitmap.device_bit = 1;
		meta.dint_metadata.output_deviceno = meta.int_metadata.device_no;
		hdr.intbitmap.iport_bit = 1;
		meta.dint_metadata.output_iport = (bit<8>)(standard_metadata.ingress_port);
		hdr.intbitmap.eport_bit = 1;
		meta.dint_metadata.output_eport = (bit<8>)(standard_metadata.egress_port);
		hdr.intbitmap.timedelta_bit = 1;
		meta.dint_metadata.output_timedelta = standard_metadata.deq_timedelta;
	}
	table set_bitmap_tbl {
		actions = {
			set_bitmap;
		}
		key = {}
		size = 1024;
		default_action = set_bitmap();
	}

	action do_deviceno() {
		hdr.intdeviceno.setValid();
		hdr.intdeviceno.device_no = meta.int_metadata.device_no;
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	table do_deviceno_tbl {
		actions = {
			do_deviceno;
		}
		key = {}
		size = 1024;
		default_action = do_deviceno();
	}

	action donot_deviceno() {
		hdr.intdeviceno.setInvalid();
	}
	table donot_deviceno_tbl {
		actions = {
			donot_deviceno;
		}
		key = {}
		size = 1024;
		default_action = donot_deviceno();
	}

	action do_iport() {
		hdr.intiport.setValid();
		hdr.intiport.ingress_port = (bit<8>)(standard_metadata.ingress_port);
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	table do_iport_tbl {
		actions = {
			do_iport;
		}
		key = {}
		size = 1024;
		default_action = do_iport();
	}

	action donot_iport() {
		hdr.intiport.setInvalid();
	}
	table donot_iport_tbl {
		actions = {
			donot_iport;
		}
		key = {}
		size = 1024;
		default_action = donot_iport();
	}

	action do_eport() {
		hdr.inteport.setValid();
		hdr.inteport.egress_port = (bit<8>)(standard_metadata.egress_port);
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	table do_eport_tbl {
		actions = {
			do_eport;
		}
		key = {}
		size = 1024;
		default_action = do_eport();
	}

	action donot_eport() {
		hdr.inteport.setInvalid();
	}
	table donot_eport_tbl {
		actions = {
			donot_eport;
		}
		key = {}
		size = 1024;
		default_action = donot_eport();
	}

	action do_timedelta() {
		hdr.inttimedelta.setValid();
		hdr.inttimedelta.timedelta = standard_metadata.deq_timedelta;
		hdr.udp.len = hdr.udp.len+16w4;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w4;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w4;
	}
	table do_timedelta_tbl {
		actions = {
			do_timedelta;
		}
		key = {}
		size = 1024;
		default_action = do_timedelta();
	}
	
	action donot_timedelta() {
		hdr.inttimedelta.setInvalid();
	}
	table donot_timedelta_tbl {
		actions = {
			donot_timedelta;
		}
		key = {}
		size = 1024;
		default_action = donot_timedelta();
	}

	action update_register() {
		dint_register.write(meta.dint_metadata.index, \
				((bit<128>)(hdr.ipv4.srcAddr)<<96) | ((bit<128>)(hdr.ipv4.dstAddr)<<64) | \
				((bit<128>)(hdr.udp.srcPort)<<48) | ((bit<128>)(hdr.udp.dstPort)<<32) | \
				((bit<128>)(hdr.ipv4.protocol)<<24) | ((bit<128>)(meta.dint_metadata.output_deviceno)<<16) | \
				((bit<128>)(meta.dint_metadata.output_iport)<<8) | (bit<128>)(meta.dint_metadata.output_eport));
		timedelta_register.write(meta.dint_metadata.index, meta.dint_metadata.output_timedelta);
	}
	table update_register_tbl {
		actions = {
			update_register;
		}
		key = {}
		size = 1024;
		default_action = update_register();
	}

	action update_register2() {
		dint_register2.write(meta.dint_metadata.index2, \
				((bit<128>)(hdr.ipv4.srcAddr)<<96) | ((bit<128>)(hdr.ipv4.dstAddr)<<64) | \
				((bit<128>)(hdr.udp.srcPort)<<48) | ((bit<128>)(hdr.udp.dstPort)<<32) | \
				((bit<128>)(hdr.ipv4.protocol)<<24) | ((bit<128>)(meta.dint_metadata.output_deviceno)<<16) | \
				((bit<128>)(meta.dint_metadata.output_iport)<<8) | (bit<128>)(meta.dint_metadata.output_eport));
		timedelta_register2.write(meta.dint_metadata.index2, meta.dint_metadata.output_timedelta);
	}
	table update_register2_tbl {
		actions = {
			update_register2;
		}
		key = {}
		size = 1024;
		default_action = update_register2();
	}

	action update_register3() {
		dint_register3.write(meta.dint_metadata.index3, \
				((bit<128>)(hdr.ipv4.srcAddr)<<96) | ((bit<128>)(hdr.ipv4.dstAddr)<<64) | \
				((bit<128>)(hdr.udp.srcPort)<<48) | ((bit<128>)(hdr.udp.dstPort)<<32) | \
				((bit<128>)(hdr.ipv4.protocol)<<24) | ((bit<128>)(meta.dint_metadata.output_deviceno)<<16) | \
				((bit<128>)(meta.dint_metadata.output_iport)<<8) | (bit<128>)(meta.dint_metadata.output_eport));
		timedelta_register3.write(meta.dint_metadata.index2, meta.dint_metadata.output_timedelta);
	}
	table update_register3_tbl {
		actions = {
			update_register3;
		}
		key = {}
		size = 1024;
		default_action = update_register3();
	}

	action set_timedelta(bit<32> timedelta) {
		standard_metadata.deq_timedelta = timedelta;
	}
	table set_timedelta_tbl {
		actions = {
			set_timedelta;	
		}
		key = {
			standard_metadata.egress_port:exact;
		}
		size = 1024;
	}

	action remove_softhard_diff() {
		standard_metadata.deq_timedelta = standard_metadata.deq_timedelta>>7; // /100
	}
	table remove_softhard_diff_tbl {
		actions = {
			remove_softhard_diff;
		}
		key = {}
		size = 1024;
		default_action = remove_softhard_diff();
	}
	
    apply {
		set_timedelta_tbl.apply(); // Simulate heavy latency
		remove_softhard_diff_tbl.apply(); // Remove difference between software simulation and hardware environment
        egress_counter.count((bit<32>)standard_metadata.egress_port);
        if (hdr.sr.isValid()) {
			dint_hash_tbl.apply();
			read_register_tbl.apply();
			parse_register_tbl.apply();
			dint_hash2_tbl.apply();
			read_register2_tbl.apply();
			parse_register2_tbl.apply();
			dint_hash3_tbl.apply();
			read_register3_tbl.apply();
			parse_register3_tbl.apply();
			if (hdr.ipv4.srcAddr == meta.dint_metadata.srcAddr && hdr.ipv4.dstAddr == meta.dint_metadata.dstAddr && hdr.ipv4.protocol == meta.dint_metadata.protocol && hdr.udp.srcPort == meta.dint_metadata.srcPort && hdr.udp.dstPort == meta.dint_metadata.dstPort) {
				// If flowkey matches, keep loaded prev metadata
				// Delta calculation (set bitmap according to delta)
				delta_calc_tbl.apply();
			}
			else if (hdr.ipv4.srcAddr == meta.dint_metadata.srcAddr2 && hdr.ipv4.dstAddr == meta.dint_metadata.dstAddr2 && hdr.ipv4.protocol == meta.dint_metadata.protocol2 && hdr.udp.srcPort == meta.dint_metadata.srcPort2 && hdr.udp.dstPort == meta.dint_metadata.dstPort2) {
				delta_calc2_tbl.apply();
			}
			else if (hdr.ipv4.srcAddr == meta.dint_metadata.srcAddr3 && hdr.ipv4.dstAddr == meta.dint_metadata.dstAddr3 && hdr.ipv4.protocol == meta.dint_metadata.protocol3 && hdr.udp.srcPort == meta.dint_metadata.srcPort3 && hdr.udp.dstPort == meta.dint_metadata.dstPort3) {
				delta_calc3_tbl.apply();
			}
			else {
				// Set bitmap as <1, 1, 1>
				set_bitmap_tbl.apply();
			}
			if (hdr.intbitmap.device_bit == 1) {
				do_deviceno_tbl.apply();
			}
			else {
				donot_deviceno_tbl.apply();
			}
			if (hdr.intbitmap.iport_bit == 1) {
				do_iport_tbl.apply();
			}
			else {
				donot_iport_tbl.apply();
			}
			if (hdr.intbitmap.eport_bit == 1 ) {
				do_eport_tbl.apply();
			}
			else {
				donot_eport_tbl.apply();
			}
			if (hdr.intbitmap.timedelta_bit == 1) {
				do_timedelta_tbl.apply();
			}
			else {
				donot_timedelta_tbl.apply();
			}
			update_register_tbl.apply();
			update_register2_tbl.apply();
			update_register3_tbl.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    counter(COUNTER_SIZE,CounterType.packets) ingress_counter;

    @name("_drop")
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name("l2setmetadata")
    action l2setmetadata(bit<9> port) {
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }
    @name("l2setmetadataecmp")
    action l2setmetadataecmp(bit<2> routeNum, bit<16> portData) {
        bit<32> result=32w0;
        random(result,32w0,(bit<32>)(routeNum-2w1));
        bit<16> data=portData;
        if (result == 32w1) {
            data=portData>>4;
        }else if(result == 32w2){
            data=portData>>8;
        }else if(result==32w3){
            data=portData>>4;
            data=portData>>8;
        }
        bit<9> port=(bit<9>)((bit<4>)data);
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }
    @name("arpreply")
    action arpreply(bit<48>repmac) {
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        standard_metadata.egress_port = standard_metadata.ingress_port;
        hdr.ethernet.srcAddr=repmac;
        hdr.ethernet.dstAddr=hdr.arp.arpSha;
        bit<32> tempip;
        tempip=hdr.arp.arpSpa;
        hdr.arp.arpSpa=hdr.arp.arpTpa;
        hdr.arp.arpTpa=tempip;
        hdr.arp.arpTha=hdr.arp.arpSha;
        hdr.arp.arpSha=repmac;
    }
    @name("srrouting")
    action srrouting() {
        // read 8 bit from routingList use listPosition
        // and set it to egress metadata
        bit<8> port=(bit<8>)hdr.sr.routingList;
        hdr.sr.routingList=hdr.sr.routingList>>8;
        standard_metadata.egress_spec = (bit<9>)port+9w1; // 0 -> eth1
        standard_metadata.egress_port = (bit<9>)port+9w1;
    }
    @name("setdeviceno")
    action setdeviceno(bit<8> device_no) {
        meta.int_metadata.device_no=device_no;
    }

    @name("dotrans")
    table dotrans {
        actions = {
            l2setmetadataecmp;
            NoAction;
        }
        key = {
            hdr.ethernet.srcAddr:exact;
            hdr.ethernet.dstAddr:exact;
        }
        size=512;
        default_action=NoAction();
    }
    @name("dosocket")
    table dosocket {
        actions = {
            l2setmetadata;
            NoAction;
        }
        key = {
            hdr.udp.dstPort:exact;
        }
        size=512;
        default_action=NoAction();
    }
    @name("doarp")
    table doarp {
        actions = {
            arpreply;
            NoAction;
        }
        key = {
            //hdr.arp.arpTha:exact;
            hdr.arp.arpTpa:exact;
        }
        size=512;
        default_action=NoAction();
    }
    @name("dosr")
    table dosr {
        actions = {
            srrouting;
        }
        key={}
        size=512;
        default_action=srrouting();
    }
    @name("setmetadata")
    table setmetadata {
        actions = {
            setdeviceno;
            NoAction;
        }
        key={}
        size=512;
        default_action=NoAction();
    }
    apply { 
        setmetadata.apply();
        if (hdr.ipv4.isValid()) {
            if(hdr.sr.isValid()) {
                dosr.apply();
            }else{
                dotrans.apply();
                dosocket.apply();
            }
        } else if(hdr.arp.isValid()) {
            doarp.apply();
        }
        ingress_counter.count((bit<32>)standard_metadata.ingress_port);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
