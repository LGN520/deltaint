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
//#define BUCKET_COUNT 8192
#define BUCKET_COUNT 32768
#endif

// we can change TTL mask based on data center topology and switch location to add per-node bitmap&state dynamically
#define INGRESS_TTL_MASK 0
#define EGRESS_TTL_MASK 1

#include "p4src/header.p4"
#include "p4src/parser.p4"

#include "p4src/regs/flowkey.p4"
#include "p4src/regs/latency.p4"

#include "p4src/ingress.p4"
#include "p4src/egress.p4"

control ingress {
	// Stage 0
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(ipv4_lpm); // set egress port
	}
}

control egress {
	// Stage 0
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(set_egmeta_tbl); // set current latency and ttl
		apply(update_srcip_dstip_tbl);
		apply(update_srcport_dstport_tbl);
		apply(update_protocol_tbl);
	}

	// Stage 1
	if (udp_hdr.dstPort == DINT_DSTPORT) {
		apply(update_latency_tbl);
	}

	// Stage 2
	if (udp_hdr.dstPort == DINT_DSTPORT) { // use gateway instead of exact matching to make such judgement, so the default action of latency_insert_tbl will no be accessed by non-INT packets
		apply(latency_insert_tbl); // we cannot perform range matching on latency delta in egress pipeline due to Tofino TCAM limitation -> we do NOT merge latency_insert_tbl into metadata_insert_tbl, such that we can use default action to insert complete latency state
	}
}
