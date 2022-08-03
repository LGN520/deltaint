#include "tofino/intrinsic_metadata.p4"
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/constants.p4"
#include "tofino/primitives.p4"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define PROTOTYPE_TCP 0x06
#define PROTOTYPE_UDP 0x11

#define DINT_DSTPORT 1234

// for debug mode
//#define DEBUG

#ifdef DEBUG
#define BUCKET_COUNT 1
#else
#define BUCKET_COUNT 8192
#endif

// we can change TTL mask based on data center topology and switch location to add state dynamically
#define INGRESS_TTL_MASK 0
#define EGRESS_TTL_MASK 1

#include "p4src/header.p4"
#include "p4src/parser.p4"

#include "p4src/regs/flowkey.p4"

#include "p4src/ingress.p4"
#include "p4src/egress.p4"

control ingress {
	// Stage 0
	apply(ipv4_lpm); // set egress port
}

control egress {
	// Stage 0
	apply(set_egmeta_tbl); // set device id
	if (ipv4_hdr.ttl == 64) {
		apply(update_srcip_dstip_tbl);
		apply(update_srcport_dstport_tbl);
		apply(update_protocol_tbl);
	}

	// Stage 1
	if (ipv4_hdr.ttl == 64) {
		apply(set_deviceid_bit_tbl); // set ttl; may change int_hdr.deviceid_bit
	}
	else {
		apply(set_deviceid_tbl); // set ttl
	}
}
