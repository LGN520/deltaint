#include "tofino/intrinsic_metadata.p4"
#include "tofino/stateful_alu_blackbox.p4"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define PROTOTYPE_TCP 0x06
#define PROTOTYPE_UDP 0x11

/* Packet Header Types */

header_type ethernet_t {
	fields {
		dstAddr: 48;
		srcAddr: 48;
		etherType: 16;
	}
}

header_type ipv4_t {
	fields {
		version: 4;
		ihl: 4;
		diffserv: 8;
		totalLen: 16;
		identification: 16;
		flags: 3;
		fragOffset: 13;
		ttl: 8;
		protocol: 8;
		hdrChecksum: 16;
		srcAddr: 32;
		dstAddr: 32;
	}
}

header_type udp_t {
	fields {
		srcPort: 16;
		dstPort: 16;
		hdrLength: 16;
		checksum: 16;
	}
}

header_type int_t {
	fields {
		/* TODO: Your Custom Header Type */
		deviceid: 8;
	}
}

header_type metadata_t {
	fields {
		/* TODO: Your Metadata */
		deviceid: 8;

		//hashidx: 32;
		int_flowkey_predicate: 4;
		rsvd: 4;
	}
}

header ethernet_t ethernet_hdr;
header ipv4_t ipv4_hdr;
header udp_t udp_hdr;
header int_t int_hdr;
metadata metadata_t meta;

/* Parser */

parser start {
	return parse_ethernet;
}

parser parse_ethernet {
	extract(ethernet_hdr);
	return select(ethernet_hdr.etherType) {
		ETHERTYPE_IPV4: parse_ipv4;
		default: ingress;
	}
}

parser parse_ipv4 {
	extract(ipv4_hdr);
	return select(ipv4_hdr.protocol) {
		PROTOTYPE_UDP: parse_udp;
		default: ingress;
	}
}

parser parse_udp {
	extract(udp_hdr);
	return parse_int;
}

parser parse_int {
	extract(int_hdr);
	return ingress;
}

/* Ingress Processing (Normal Operation) */

action nop() {

}

action droppkt() {
	drop();
}

action ipv4_forward(port) {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
	add_to_field(ipv4_hdr.ttl, -1);
}

table ipv4_lpm {
	reads {
		ipv4_hdr.dstAddr: lpm;
	}
	actions {
		ipv4_forward;
		droppkt;
		nop;
	}
	default_action: droppkt();
	size: 1024;
}

action set_igmeta(deviceid) {
	modify_field(meta.deviceid, deviceid);
}

table set_igmeta_tbl {
	actions {
		set_igmeta;
	}
	default_action: set_igmeta(1);
}

/* Ingress Processing */

control ingress {
	if (valid(udp_hdr)) {
		// Configure device ID
		apply(set_igmeta_tbl);

		apply(ipv4_lpm);
	}
}

/* Egress Processing */

/* C4 Sketching */

field_list hash_fields {
	ipv4_hdr.srcAddr;
	ipv4_hdr.dstAddr;
}

field_list_calculation hash_field_calc {
	input {
		hash_fields;
	}
#ifdef BMV2TOFINO
	algorithm: crc32;
#else
	algorithm: random;
#endif
	output_width: 32;
}

/*action calculate_hash() {
	modify_field_with_hash_based_offset(meta.hashidx, 0, hash_field_calc, 32768);
}

table calculate_hash_tbl {
	actions {
		calculate_hash;
	}
	default_action: calculate_hash();
}*/

// 256 KB in total

register int_flowkey_reg {
	width: 64; // low: srcip; high: dstip
	instance_count: 32768;
}

blackbox stateful_alu int_flowkey_alu {
	reg: int_flowkey_reg;

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

	output_value: predicate;
	output_dst: meta.int_flowkey_predicate;
}

action update_flowkey_sketch() {
	int_flowkey_alu.execute_stateful_alu_from_hash(hash_field_calc);
	//int_flowkey_alu.execute_stateful_alu(meta.hashidx);
}

table update_flowkey_sketch_tbl {
	actions {
		update_flowkey_sketch;
	}
	default_action: update_flowkey_sketch();
}

action set_deviceid() {
	modify_field(int_hdr.deviceid, meta.deviceid);
}

table set_deviceid_tbl {
	actions {
		set_deviceid;
	}
	default_action: set_deviceid();
}

control egress {
	// StateLoading, DeltaCalculation, and StateUpdate
	//apply(calculate_hash_tbl);
	apply(update_flowkey_sketch_tbl);

	// StateInsert
	if (meta.int_flowkey_predicate != 8) {
		apply(set_deviceid_tbl);
	}
}
