#include "tofino/intrinsic_metadata.p4"
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/constants.p4"
#include "tofino/primitives.p4"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define PROTOTYPE_TCP 0x06
#define PROTOTYPE_UDP 0x11

#define DINT_DSTPORT 1234
#define THRESHOLD 1
#define THRESHOLD_PLUS_ONE 2

// for debug mode
//#define DEBUG

#ifdef DEBUG
#define BUCKET_COUNT 1
#else
//#define BUCKET_COUNT 16384
#define BUCKET_COUNT 65536
#endif

#include "p4src/header.p4"
#include "p4src/parser.p4"

#include "p4src/regs/flowkey.p4"
#include "p4src/regs/power.p4"

#include "p4src/ingress.p4"
#include "p4src/egress.p4"

control ingress {
	// Stage 0
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(ipv4_lpm); // set egress port and ttl
	}
}

control egress {
	// Stage 0
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(set_egmeta_tbl); // set current power
		apply(update_srcip_dstip_tbl);
		apply(update_protocol_tbl);
	}

	// Stage 1 (cannot place into stage 0 due to SRAM limitation)
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(update_srcport_dstport_tbl);
	}

	// Stage 2
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(update_previnput_tbl);
	}

	// Stage 3
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(set_output_tbl);
	}

	// Stage 4
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(update_prevoutput_tbl);
	}

	// Stage 5
	if (udp_hdr.dstPort == DINT_DSTPORT) { // use gateway instead of exact matching to make such judgement, so the default action of power_insert_tbl will no be accessed by non-INT packets
		apply(power_insert_tbl); // we cannot perform range matching on power delta in egress pipeline due to Tofino TCAM limitation
	}
}
