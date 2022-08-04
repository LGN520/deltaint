#ifdef DTEL_REPORT_ENABLE
@pragma not_parsed egress
@pragma not_deparsed ingress
@pragma not_parsed ingress
header dtel_report_header_t dtel_report_header;

#define DTEL_REPORT_NEXT_PROTO_ETHERNET         0
#define DTEL_REPORT_NEXT_PROTO_MOD              1
#define DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL     2

parser parse_dtel_report {
    extract(dtel_report_header);
    // doesn't matter what we match on
    return select(current(0,8)) {
        default : ingress;
        // For deparser only
#if defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)
        DTEL_REPORT_NEXT_PROTO_MOD : parse_mirror_on_drop;
#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE
#ifdef INT_ENABLE
        DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL : parse_all_int_meta_value_headers;
#endif // INT_ENABLE
#ifdef POSTCARD_ENABLE
        DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL : parse_postcard_header;
#endif // POSTCARD_ENABLE
    }
}

parser parse_only_inner_ethernet {
    extract(inner_ethernet);
    return ingress;
}

#endif // DTEL_REPORT_ENABLE

#if defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)
@pragma pa_no_overlay egress  mirror_on_drop_header.egress_port
@pragma pa_no_overlay egress  mirror_on_drop_header.ingress_port
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header mirror_on_drop_header_t mirror_on_drop_header;

parser parse_mirror_on_drop {
    extract(mirror_on_drop_header);
// only for deparser. don't use parse_inner_ethernet as it mis-leads the phv-allocation
    return parse_only_inner_ethernet;
}
#endif /* DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE */

#ifdef POSTCARD_ENABLE
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header postcard_header_t postcard_header;

parser parse_postcard_header {
    extract(postcard_header);
// only for deparser. don't use parse_inner_ethernet as it mis-leads the phv-allocation
    return parse_only_inner_ethernet;
}
#endif // POSTCARD_ENABLE

#ifdef INT_ENABLE

#ifdef INT_EP_ENABLE
@pragma not_parsed egress
#endif
header int_header_t                             int_header;
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header int_switch_id_header_t                   int_switch_id_header;
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header int_port_ids_header_t                    int_port_ids_header;
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header int_q_occupancy_header_t                 int_q_occupancy_header;
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header int_ingress_tstamp_header_t              int_ingress_tstamp_header;
@pragma not_parsed ingress
@pragma not_deparsed ingress
@pragma not_parsed egress
header int_egress_tstamp_header_t               int_egress_tstamp_header;

#define INT_TYPE_INT                           0x01
#define INT_TYPE_DIGEST_INT                    0x03

#ifdef INT_OVER_L4_ENABLE
#define INT_EXIT_SINK  ingress
#else
#define INT_EXIT_SINK  parse_inner_ethernet
#endif

// Transit egress goes to ingress after this
// Transit egress deparser uses all_int_meta to put packet together then ingress state
// Source egress deparser uses all_int_meta to put packet together
// then rest of headers
// Sink egress loops through the stack and goes through the rest of headers
// Sink ingress total_hop_cnt == 0, rest of headers
// Sink e2e egress deparser uses all_int_meta to put packet together
// then inner_ethernet
// Source ingress, sink egress, and sink i2e egress don't reach here
parser parse_int_header {
    extract(int_header);
#ifdef INT_EP_ENABLE
    // allows int_header to go to tphv at ingress
    set_metadata(int_metadata.digest_enb, latest.d);
#endif
    return select (latest.rsvd1, latest.total_hop_cnt) {
        // reserved bits = 0 and total_hop_cnt == 0
        // no int_values are added by upstream
#ifdef INT_EP_ENABLE
        0x000 mask 0xfff: INT_EXIT_SINK;
#endif
#ifdef INT_TRANSIT_ENABLE
        0x000 mask 0xfff: ingress;
#endif // TRANSIT

#ifdef INT_EP_ENABLE
        // parse INT hop headers added by upstream devices (total_hop_cnt != 0)
        // reserved bits must be 0
        0x000 mask 0x300: parse_int_stack;
#endif
        0 mask 0: ingress;
        // never transition to the following state
        default: parse_all_int_meta_value_headers;
    }
}

#ifdef INT_EP_ENABLE

// sink removes the stack in the ingress parser using force shift

// intl45_head_header.len includes the length of stack + head + int_header = 3 words
// The following states remove the stack using states of two types. Level 1 (L1) and Level 2 (L2).
// The force shift value at L1 nodes considers that the length includes that 4 words.
// Here is how the parse states may call each other.
// This uses much fewer states than a loop that removes one word at a time
// L1-16
//   - L2-8
//       - L2-4
//       - L2-3
//       - L2-2
//       - L2-1
//   - L2-4
//   - L2-3
//   - L2-2
//   - L2-1
// L1-8
//   - L2-4
//   - L2-3
//   - L2-2
//   - L2-1
// L1-4
//   - L2-3
//   - L2-2
//   - L2-1

@pragma terminate_parsing ingress
parser parse_int_stack {
    return select(intl45_head_header.len) {
        0x10 mask 0x10    : parse_int_stack_L1_16_1;
        0x08 mask 0x08    : parse_int_stack_L1_8;
#ifdef INT_L45_DSCP_ENABLE
        0x04 mask 0x04    : parse_int_stack_L1_4;
        0x03 mask 0x03    : INT_EXIT_SINK;
#endif
#ifdef INT_L45_MARKER_ENABLE
        0x07 mask 0x07    : parse_int_stack_L2_2;
        0x06 mask 0x07    : parse_int_stack_L2_1;
        0x05 mask 0x07    : INT_EXIT_SINK;
#endif
        // intl45_head_header.len is in word length
        // len is always >=3 because head and int_header are 3 words
        // In case 8B probe marker is used, len is always >= 5 words.
        default : ingress;
    }
}

// Remove 13 words instead of 16 as 3 words are for head and int headers not stack
// In case 8B probe marker is used, the stack is only 11 words.
// split into three states because of limitation in force_shift
#ifdef INT_L45_DSCP_ENABLE
@pragma force_shift egress 160
#endif
#ifdef INT_L45_MARKER_ENABLE
@pragma force_shift egress 96
#endif
parser parse_int_stack_L1_16_1{
    return parse_int_stack_L1_16_2;
}

@pragma force_shift egress 128
parser parse_int_stack_L1_16_2{
    return parse_int_stack_L1_16_3;
}

@pragma force_shift egress 128
parser parse_int_stack_L1_16_3{
    return select(intl45_head_header.len) {
        0x08 mask 0x08    : parse_int_stack_L2_8_1;
        0x04 mask 0x04    : parse_int_stack_L2_4;
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

// Remove 5 words instead of 8 as 3 words are for head and int headers, not stack
// In case 8B probe marker is used, the stack is only 3 words.
#ifdef INT_L45_DSCP_ENABLE
@pragma force_shift egress 160
#endif
#ifdef INT_L45_MARKER_ENABLE
@pragma force_shift egress 96
#endif
parser parse_int_stack_L1_8{
    return select(intl45_head_header.len) {
        0x04 mask 0x04    : parse_int_stack_L2_4;
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

// Remove 1 word instead of 4 as 3 words are for head and int headers not stack
@pragma force_shift egress 32
parser parse_int_stack_L1_4{
    return select(intl45_head_header.len) {
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

@pragma force_shift egress 128
// split into two states because of limitation in force_shift
parser parse_int_stack_L2_8_1{
    return parse_int_stack_L2_8_2;
}

@pragma force_shift egress 128
parser parse_int_stack_L2_8_2{
    return select(intl45_head_header.len) {
        0x04 mask 0x04    : parse_int_stack_L2_4;
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

@pragma force_shift egress 128
parser parse_int_stack_L2_4{
    return select(intl45_head_header.len) {
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

// 3 is to optimize 1 state
@pragma force_shift egress 96
parser parse_int_stack_L2_3{
    return INT_EXIT_SINK;
}

@pragma force_shift egress 64
parser parse_int_stack_L2_2{
    return INT_EXIT_SINK;
}

@pragma force_shift egress 32
parser parse_int_stack_L2_1{
    return INT_EXIT_SINK;
}

#endif // INT_EP_ENABLE

parser parse_all_int_meta_value_headers {
    // bogus state.. just extract all possible int headers in the
    // correct order to build
    // the correct parse graph for deparser (while adding headers)
    extract(int_switch_id_header);
    extract(int_port_ids_header);
    extract(int_q_occupancy_header);
    extract(int_ingress_tstamp_header);
    extract(int_egress_tstamp_header);
    // doesn't matter which field to use
    // select is there to make pathes for deparser
    return select(current(0,8)){
        // for source L45 and VXLAN
        0   mask 0 : INT_EXIT_SINK;
        // A path to inner_ethernet for e2e
        default    : parse_only_inner_ethernet;
    }
}

#ifdef INT_OVER_L4_ENABLE
@pragma pa_container_size egress intl45_marker_header.f0 32
@pragma pa_container_size egress intl45_marker_header.f1 32
header intl45_marker_header_t  intl45_marker_header;

header intl45_head_header_t  intl45_head_header;

parser parse_intl45_ipv4{
    extract(ipv4);
#if defined(PARSER_EXTRACT_OUTER_ENABLE)
    set_metadata(l3_metadata.lkp_ip_proto, latest.protocol);
    set_metadata(l3_metadata.lkp_ip_ttl, latest.ttl);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
    return select(latest.flags, latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_ICMP mask 0x3ffffff : parse_intl45_icmp;  // ipv4.ihl=5, No fragmentation.
        IP_PROTOCOLS_IPHL_TCP  mask 0x3ffffff : parse_intl45_tcp;  // ipv4.ihl=5, No fragmentation.
        IP_PROTOCOLS_IPHL_UDP  mask 0x3ffffff : parse_intl45_udp;  // ipv4.ihl=5, No fragmentation.
        0x2000000 mask 0x3fff000 : parse_intl45_ipv4_fragmented_first_pkt;  // fragmented, ipv4.fragOffset=0
        // Non-udp/tcp/icmp packets  do NOT have INT headers and never hit this parser state.
        0 mask 0x3fff000 : ingress; // No fragmentation.
        default : parse_intl45_ipv4_fragmented_other_pkt; // fragmented with non-zero offset.
    }
}

parser parse_intl45_ipv4_fragmented_first_pkt {
    set_metadata(l3_metadata.lkp_ip_frag, 3);
    return select(ipv4.ihl, ipv4.protocol) {
        IP_PROTOCOLS_IPHL_ICMP : parse_intl45_icmp;
        IP_PROTOCOLS_IPHL_TCP : parse_intl45_tcp;
        IP_PROTOCOLS_IPHL_UDP : parse_intl45_udp;
        default : ingress;  // ipv4.ihl>5
    }
}

parser parse_intl45_ipv4_fragmented_other_pkt {
    set_metadata(l3_metadata.lkp_ip_frag, 2);
    return ingress;
}

parser parse_intl45_icmp {
    extract(icmp);
#if defined(PARSER_EXTRACT_OUTER_ENABLE)
    set_metadata(l3_metadata.lkp_l4_sport, latest.typeCode);
#else
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.typeCode);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */

    return parse_intl45_head_header;
}

parser parse_intl45_tcp {
    extract(tcp);
#if defined(PARSER_EXTRACT_OUTER_ENABLE)
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
#else
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);
#ifndef TUNNEL_DISABLE
    set_metadata(l3_metadata.lkp_outer_tcp_flags, latest.flags);
#endif
#endif /* PARSER_EXTRACT_OUTER_ENABLE */

    return parse_intl45_head_header;
}

parser parse_intl45_udp {
    extract(udp);
#if defined(PARSER_EXTRACT_OUTER_ENABLE)
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
#else
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */

    return parse_intl45_head_header;
}

parser parse_intl45_head_header{
#ifdef INT_L45_MARKER_ENABLE
    extract(intl45_marker_header);
#endif
    extract(intl45_head_header);
    return parse_int_header;
}

#endif // INT_OVER_L4_ENABLE

#endif // INT_ENABLE
