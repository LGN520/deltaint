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

#ifdef INT_EP_ENABLE

/*******************************************************************************
 INT over L4 ingress control process_int_watchlist_
 Apply watchlist only for supported L4 protocols in INT over L4
*******************************************************************************/
control process_int_watchlist_ {
    if ((int_metadata.postcard_mode == 1) or
        ((valid(tcp) or valid(udp) or valid(icmp)) and ipv4.ihl == 5)) {
        apply(int_watchlist);
    }
}

#endif // INT_EP_ENABLE

/*******************************************************************************
  clear intl45 dscp actions used by
  int_set_sink table at ingress
  int_edge_ports table at egress
  dtel_intl45_set_dscp at egress
*******************************************************************************/

#ifdef INT_L45_DSCP_ENABLE

/* Set ipv4.diffserv using configured int.l45_dscp value<<2 and mask<<2, or
 * clear ipv4.diffserv using diffserv_value 0 and int.l45_dscp_mask<<2 */
action intl45_set_dscp_all(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, INTL45_DIFFSERV_MASK_ALL);
}
/* Set ipv4.diffserv using configured int.l45_dscp value<<2 and mask<<2, or
 * clear ipv4.diffserv using ~int.l45_dscp_value<<2 and int.l45_dscp_mask<<2 */
action intl45_set_dscp_2(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, 0x04);
}
action intl45_set_dscp_3(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, 0x08);
}
action intl45_set_dscp_4(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, 0x10);
}
action intl45_set_dscp_5(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, 0x20);
}
action intl45_set_dscp_6(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, 0x40);
}
action intl45_set_dscp_7(diffserv_value) {
    modify_field(ipv4.diffserv, diffserv_value, 0x80);
}

#ifdef INT_EP_ENABLE

action int_sink_set_l45_dscp_clear_all(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_all(diffserv_value);
}
action int_sink_set_l45_dscp_clear_2(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_2(diffserv_value);
}
action int_sink_set_l45_dscp_clear_3(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_3(diffserv_value);
}
action int_sink_set_l45_dscp_clear_4(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_4(diffserv_value);
}
action int_sink_set_l45_dscp_clear_5(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_5(diffserv_value);
}
action int_sink_set_l45_dscp_clear_6(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_6(diffserv_value);
}
action int_sink_set_l45_dscp_clear_7(sink_bit, diffserv_value) {
    modify_field(int_metadata.sink, sink_bit);
    modify_field(int_metadata.postcard_mode, 0);
    intl45_set_dscp_7(diffserv_value);
}

action int_convert_word_to_byte_l45_dscp_clear_all(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_all(diffserv_value);
}
action int_convert_word_to_byte_l45_dscp_clear_2(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_2(diffserv_value);
}
action int_convert_word_to_byte_l45_dscp_clear_3(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_3(diffserv_value);
}
action int_convert_word_to_byte_l45_dscp_clear_4(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_4(diffserv_value);
}
action int_convert_word_to_byte_l45_dscp_clear_5(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_5(diffserv_value);
}
action int_convert_word_to_byte_l45_dscp_clear_6(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_6(diffserv_value);
}
action int_convert_word_to_byte_l45_dscp_clear_7(diffserv_value) {
    int_convert_word_to_byte();
    intl45_set_dscp_7(diffserv_value);
}

#endif // INT_EP_ENABLE
#endif // INT_L45_DSCP_ENABLE

#ifdef INT_EP_ENABLE

/*******************************************************************************
 int_terminate table invoked in dtel_int.p4, at egress
*******************************************************************************/

action int_sink_update_intl45_v4() {
#ifdef INT_L45_MARKER_ENABLE
    remove_header(intl45_marker_header);
#endif // INT_L45_MARKER_ENABLE
    remove_header(intl45_head_header);
    subtract(ipv4.totalLen, ipv4.totalLen, intl45_head_header.len);
    subtract(int_metadata.l4_len, -1, intl45_head_header.len);
    int_remove_header();
}

action int_sink_update_intl45_v4_udp() {
    int_sink_update_intl45_v4();
#ifdef INT_L4_UDP_CHECKSUM_ZERO_ENABLE
    modify_field(udp.checksum, 0);
#endif
    subtract(udp.length_, udp.length_, intl45_head_header.len);
}

table int_terminate {
    // This table is used to update the outer(underlay) headers on int_sink
    // to reflect removal of INT headers
    // 0 => update ipv4 and intl45 headers
    // 1 => update ipv4 and intl45 headers + udp
    reads {
        udp : valid;
    }
    actions {
        int_sink_update_intl45_v4;
        int_sink_update_intl45_v4_udp;
    }
    size : 3;
}

#endif // INT_EP_ENABLE


/*******************************************************************************
 INT over L4 egress control process_int_outer_encap_
 At source and transit updates the outer encap headers
 add/update IP and INT shim headers in int_outer_encap table
*******************************************************************************/

control process_int_outer_encap_ {
    apply(int_outer_encap);
}

#ifdef INT_TRANSIT_ENABLE
action int_update_l45_ipv4() {
    add_to_field(ipv4.totalLen, int_metadata.insert_byte_cnt);
    modify_field(int_metadata.l4_len, int_metadata.insert_byte_cnt);
    add_to_field(intl45_head_header.len, int_metadata.int_hdr_word_len);
}

action int_update_l45_ipv4_udp() {
    int_update_l45_ipv4();

    add_to_field(udp.length_, int_metadata.insert_byte_cnt);
#ifdef INT_L4_UDP_CHECKSUM_ZERO_ENABLE
    modify_field(udp.checksum, 0);
#endif
}

// Applies at transit to update the outer header
// Add entry at transit enable
// int_outer_encap runs for not mirrored packets
// only expects mirror_on_drop_encap to run for mirror pkts
@pragma ignore_table_dependency mirror_on_drop_encap
table int_outer_encap {
    reads {
        ipv4 : valid;
        udp  : valid;
    }
    actions {
        int_update_l45_ipv4;
        int_update_l45_ipv4_udp;
        nop;
    }
    default_action: nop;
    size : 4;
}
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE

action intl45_add_marker(f0, f1){
    add_header(intl45_marker_header);
    modify_field(intl45_marker_header.f0, f0);
    modify_field(intl45_marker_header.f1, f1);
}

#ifdef INT_L45_MARKER_ENABLE
action int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt,
    marker_f0, marker_f1){
#else
action int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt){
#endif
    // INT source
    // Add the INT_L45 shim layer
    add_header(intl45_head_header);
    modify_field(intl45_head_header.int_type, int_type);
    modify_field(intl45_head_header.len, total_words);
    modify_field(intl45_head_header.rsvd1, 0);
    add_to_field(ipv4.totalLen, insert_byte_cnt);
    modify_field(int_metadata.l4_len, insert_byte_cnt);
#ifdef INT_L45_MARKER_ENABLE
    intl45_add_marker(marker_f0 , marker_f1);
#endif // INT_L45_MARKER_ENABLE
}

#ifdef INT_L45_MARKER_ENABLE
action int_add_update_l45_ipv4_udp(int_type, total_words, insert_byte_cnt,
    marker_f0, marker_f1){
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt,
    marker_f0, marker_f1);
#else
action int_add_update_l45_ipv4_udp(int_type, total_words, insert_byte_cnt){
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
#endif
    add_to_field(udp.length_, insert_byte_cnt);
#ifdef INT_L4_UDP_CHECKSUM_ZERO_ENABLE
    modify_field(udp.checksum, 0);
#endif

}

// int_outer_encap runs for not mirrored packets
// only expects mirror_on_drop_encap to run for mirror pkts
@pragma ignore_table_dependency mirror_on_drop_encap
// too many exact match table at last stage using all hash bits
#ifndef L3_HEAVY_INT_LEAF_PROFILE
@pragma ternary 1
#endif
table int_outer_encap {
// This table is applied only if it is decided to add INT info
// as part of source functionality
// int_config_session id, proto    :
// ID                   , ICMP/TCP : add_update_l45
// ID                   , UDP      : add_update_l45_udp
    reads {
        int_metadata.config_session_id : exact;
        udp         : valid;
        tcp         : valid;
        icmp        : valid;
    }
    actions {
        int_add_update_l45_ipv4;
        int_add_update_l45_ipv4_udp;
        nop;
    }
    size : DTEL_CONFIG_SESSIONS_X3;
}

#endif // INT_EP_ENABLE

/*******************************************************************************
 INT over L4 set DSCP at non-edge ports
   INT present             => set DSCP
   INT not present         => clear DSCP
 Deflected packets at sink => clear DSCP
*******************************************************************************/

#ifdef INT_L45_DSCP_ENABLE

// deflection, egress_port   int_header.v, ipv4.dscp,         action
//             == edge_port, int_md.sink
// high priority entries
// yes         *             sink = yes    *                  intl45_set_dscp(0)
// yes         *             sink = no     *                  nop
// no          yes           *             *                  nop
// low priority entries (egress_port!=edge_port even if not matched explicitly)
// no          *             int=yes       *                  intl45_set_dscp
// no          *             int=no        int.l45_dscp&mask  intl45_set_dscp(0)
// default action nop
table dtel_intl45_set_dscp {
    reads {
        int_header.valid                   : ternary;
        ipv4.diffserv                      : ternary;
#ifdef INT_EP_ENABLE
        eg_intr_md.egress_port             : ternary;
        int_metadata.sink                  : ternary;
        eg_intr_md.deflection_flag         : exact;
#endif // INT_EP_ENABLE
    }
    actions {
        intl45_set_dscp_all;
        intl45_set_dscp_2;
        intl45_set_dscp_3;
        intl45_set_dscp_4;
        intl45_set_dscp_5;
        intl45_set_dscp_6;
        intl45_set_dscp_7;
        nop;
    }
    size: DTEL_INT_L45_DSCP_TABLE_SIZE;
}
#endif /* INT_L45_DSCP_ENABLE */

control process_dtel_int_over_l4_set_dscp {
#ifdef INT_L45_DSCP_ENABLE
    apply(dtel_intl45_set_dscp);
#endif /* INT_L45_DSCP_ENABLE */
}

/*******************************************************************************
 INT over L4 DoD
   If INT present, convert length from words to bytes
*******************************************************************************/

#ifdef INT_EP_ENABLE
table dtel_intl45_convert_word_to_byte {
    actions {
        int_convert_word_to_byte;
    }
    default_action : int_convert_word_to_byte;
    size: 1;
}
#endif // INT_EP_ENABLE

control process_dtel_deflect_on_drop_ {
#ifdef INT_EP_ENABLE
    if (valid(int_header)) {
        apply(dtel_intl45_convert_word_to_byte);
    }
#endif // INT_EP_ENABLE
}
