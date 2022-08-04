/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2019 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
#define ETHERTYPE_IPV4 0x0800

#define IP_DIFFSERV_INT 0x66
#define IP_PROTOCOL_UDP 0x11

parser start {
    return select(current(96, 16)) { // ether.type
        default: parse_ethernet;
    }
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

// This ensures hdrChecksum and protocol fields are allocated to different
// containers so that the deparser can calculate the IPv4 checksum correctly.
// We are enforcing a stronger constraint than necessary. In reality, even if
// protocol and hdrChecksum are allocated to the same 32b container, it is OK
// as long as hdrChecksum occupies the first or last 16b. It should just not be
// in the middle of the 32b container. But, there is no pragma to enforce such
// a constraint precisely. So, using pa_fragment.
@pragma pa_fragment ingress ipv4.hdrChecksum
@pragma pa_fragment egress ipv4.hdrChecksum
@pragma pa_container_size ingress ipv4.dstAddr 32
@pragma pa_container_size ingress ipv4.srcAddr 32
@pragma pa_container_size egress ipv4.dstAddr 32
@pragma pa_container_size egress ipv4.srcAddr 32
header ipv4_t ipv4;

field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    //verify ipv4_checksum;
    update ipv4_checksum;
}

parser parse_ipv4 {
   return select(current(8,8)){ //ipv4.diffserv
       IP_DIFFSERV_INT: parse_intl45_ipv4;
       default: parse_ipv4_original;
    }
}

header udp_t udp;
header intl45_head_header_t intl45_head_header;
//header int_header_t int_header;
// NOTE: int stack header for C1
header int_switch_id_header_t int_switch_id_header;
@pragma pa_solitary ingress int_ingress_port_id_header.ingress_port_id
@pragma pa_solitary egress int_ingress_port_id_header.ingress_port_id
header int_ingress_port_id_header_t int_ingress_port_id_header;
@pragma pa_solitary ingress int_egress_port_id_header.egress_port_id
@pragma pa_solitary egress int_egress_port_id_header.egress_port_id
header int_egress_port_id_header_t int_egress_port_id_header;
header int_hop_latency_header_t int_hop_latency_header;

parser parse_intl45_ipv4{
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOL_UDP: parse_intl45_udp;
        default: ingress;
    }
}

parser parse_intl45_udp {
    extract(udp);
    return parse_intl45_head_header;
}

parser parse_intl45_head_header{
    extract(intl45_head_header);
    //return parse_int_header; // NOTE: ignore INT header here for fair comparison
	return parse_int_stack;
}

// Transit egress goes to ingress after this
// Transit egress deparser uses all_int_meta to put packet together then ingress state
// Source egress deparser uses all_int_meta to put packet together
// then rest of headers
// Sink egress loops through the stack and goes through the rest of headers
// Sink ingress total_hop_cnt == 0, rest of headers
// Sink e2e egress deparser uses all_int_meta to put packet together
// then inner_ethernet
// Source ingress, sink egress, and sink i2e egress don't reach here
/*parser parse_int_header {
    extract(int_header);
    return select (latest.rsvd1, latest.total_hop_cnt) {
        // reserved bits = 0 and total_hop_cnt == 0
        // no int_values are added by upstream
        0x000 mask 0xfff: ingress;

        // parse INT hop headers added by upstream devices (total_hop_cnt != 0)
        // reserved bits must be 0
        0x000 mask 0x300: parse_int_stack;
        0 mask 0: ingress;
        // never transition to the following state
        default: ingress;
    }
}*/

parser parse_int_stack {
    return select(intl45_head_header.len) {
        0x01 mask 0x01    : parse_int_stack_L2_1; // NOTE: consider one hop here for fair comparison
        // intl45_head_header.len is in word length
        // len is always >=3 because head and int_header are 3 words
        // In case 8B probe marker is used, len is always >= 5 words.
        default : ingress;
    }
}

parser parse_int_stack_L2_1{
	extract(int_switch_id_header);
    return parse_int_ingress_port_id;
}

parser parse_int_ingress_port_id {
	extract(int_ingress_port_id_header);
	return parse_int_egress_port_id;
}

parser parse_int_egress_port_id {
	extract(int_egress_port_id_header);
	return parse_int_hop_latency;
}

parser parse_int_hop_latency {
	extract(int_hop_latency_header);
	return ingress;
}

parser parse_ipv4_original {
    extract(ipv4);
	return select(ipv4.protocol) {
		IP_PROTOCOL_UDP: parse_udp;
		default: ingress;
	}
}

parser parse_udp {
    extract(udp);
	return ingress;
}
