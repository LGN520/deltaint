#include "tofino/intrinsic_metadata.p4"
#include "tofino/stateful_alu_blackbox.p4"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define PROTOTYPE_TCP 0x06
#define PROTOTYPE_UDP 0x11
#define PROTOTYPE_CROSSPIPE 0xc0

#define BUCKET_COUNT 32768

/***********************/
/* Packet Header Types */
/***********************/

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

header_type hashidx_t {
	fields {
		hashidx: 16;
	}
}

header_type int_t {
	fields {
		/* TODO: Your Custom Header Type */
		deviceid_bit: 1;
		padding: 7;
	}
}

header_type deviceid_t {
	fields {
		deviceid: 8;
	}
}

header_type metadata_t {
	fields {
		/* TODO: Your Metadata */
		int_flowkey_predicate: 4;
	}
}

header ethernet_t ethernet_hdr;
header ipv4_t ipv4_hdr;
header int_t int_hdr;
header deviceid_t deviceid_hdr;
header hashidx_t hashidx_hdr;
metadata metadata_t meta;

/***********************/
/* Parser */
/***********************/

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
		PROTOTYPE_CROSSPIPE: parse_hashidx;
		default: parse_int;
	}
}

parser parse_hashidx {
	extract(hashidx_hdr);
	return parse_int;
}

parser parse_int {
	extract(int_hdr);
	return select(int_hdr.deviceid_bit) {
		1: parse_deviceid;
		default: ingress;
	}
}

parser parse_deviceid {
	extract(deviceid_hdr);
	return ingress;
}

/***********************/
/* Ingress Processing (Normal Operation) */
/***********************/

action ipv4_forward(port) {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
	add_to_field(ipv4_hdr.ttl, -1);
	modify_field(ipv4_hdr.protocol, PROTOTYPE_CROSSPIPE);
}

table ipv4_lpm {
	reads {
		ipv4_hdr.dstAddr: lpm;
	}
	actions {
		ipv4_forward;
	}
	size: 1024;
}

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
	output_width: 16;
}

action calculate_hash() {
	modify_field_with_hash_based_offset(hashidx_hdr.hashidx, 0, hash_field_calc, BUCKET_COUNT);
}

table calculate_hash_tbl {
	actions {
		calculate_hash;
	}
	default_action: calculate_hash();
}

action set_igmeta(deviceid) {
	modify_field(deviceid_hdr.deviceid, deviceid);
}

table set_igmeta_tbl {
	actions {
		set_igmeta;
	}
	default_action: set_igmeta(1);
}

control ingress {
	// Stage 1
	apply(calculate_hash_tbl);
	apply(ipv4_lpm);
	apply(set_igmeta_tbl); // set device id
}

/***********************/
/* Egress Processing */
/***********************/

register int_flowkey_reg {
	width: 64; // low: srcip; high: dstip
	instance_count: BUCKET_COUNT;
}

blackbox stateful_alu update_flowkey_alu {
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

action update_flowkey() {
	//int_flowkey_alu.execute_stateful_alu_from_hash(hash_field_calc);
	update_flowkey_alu.execute_stateful_alu(hashidx_hdr.hashidx);
	modify_field(ipv4_hdr.protocol, PROTOTYPE_UDP); // Remove hashidx hdr
}

table update_flowkey_tbl {
	actions {
		update_flowkey;
	}
	default_action: update_flowkey();
}

action set_deviceid() {
	modify_field(int_hdr.deviceid_bit, 1);
}

table set_deviceid_tbl {
	actions {
		set_deviceid;
	}
	default_action: set_deviceid();
}

control egress {
	// StateLoading, DeltaCalculation, and StateUpdate
	apply(update_flowkey_tbl);

	// StateInsert
	if (meta.int_flowkey_predicate != 8) {
		apply(set_deviceid_tbl);
	}
}
