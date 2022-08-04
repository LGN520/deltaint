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
#ifdef INT_ENABLE

#ifdef INT_OVER_L4_ENABLE
#include "dtel_int_over_l4.p4"
#endif

header_type int_metadata_t {
    fields {
        // INT transit
        insert_byte_cnt   : 16; // ins_cnt * 4 in 16 bits
        int_hdr_word_len  : 16;  // temp variable to keep ins_cnt but 8 bits
        path_tracking_flow: 1;  // set if valid(int_header)

        // INT endpoint
        source            : 1;  // set for INT source
        sink              : 1;  // set for INT sink
        digest_enb        : 1;  // bridged i2e to show if source adds or sink
                                // received digest and signals if per-flow stful
                                // suppression is enabled
        config_session_id : 8;  // INT config session id
        upstream_digest   : 16; // for upstream flow state change detection
        bfilter_output    : 2;  // for upstream flow state change detection
        l4_len            : 16; // l4 length change for checksum update
        postcard_mode     : 1;  // indicates use of postcards rather than INT
                                // used to relax restrictions on watchlist
    }
}

#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma pa_no_overlay ingress int_metadata.config_session_id
#endif // L3_HEAVY_INT_LEAF_PROFILE
metadata int_metadata_t int_metadata;

#endif // INT_ENABLE

/*******************************************************************************
 INT tables for ingress pipeline
 Identify role (source, transit, or sink)
    sink is set by int_set_sink table, which also clears INT L45 DSCP if
      received on an edge port (note does not yet clear INT L45 DSCP if sink)
    source is set by int_watchlist table only if sink is not set
    transit if valid(int_header)

    If sink,
        if stateful suppression is enabled checks changes
        send upstream i2e report if stateful or stateless suppress see changes
    If source, nothing more than applying int_watchlist
    if transit,
        set path_tracking_flow at ingress to indicate packet had INT. Do it at
        ingress so that ingress dropped packet can also know that.
 ******************************************************************************/


/*******************************************************************************
 INT sink ingress control block process_dtel_int_sink
 if packet has int_header and endpoint is enabled
    set int_metadata.sink
    if packet has digest
      update bfilters and detect upstream flow state change (if feature is enabled)
*******************************************************************************/

control process_dtel_int_sink {
#ifdef INT_EP_ENABLE
#if !defined(GENERIC_INT_LEAF_PROFILE)
    // no harm to do it for non-int packets
    apply(dtel_make_upstream_digest);
    apply(int_set_sink) {
        int_sink_enable {
#else
    if (int_metadata.sink == 1) { {
#endif // !GENERIC_INT_LEAF_PROFILE
#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
            if (int_metadata.digest_enb == 1) {
                // Note: cannot let control plane choose default action for
                // bfilter tables as miss action doesn't enable hash module
                process_dtel_upstream_change();
            }
#endif // DTEL_FLOW_STATE_TRACK_ENABLE
        }
    }
#endif // INT_EP_ENABLE
}

control process_dtel_make_upstream_digest {
#ifdef INT_EP_ENABLE
    apply(dtel_make_upstream_digest);
#endif
}

control process_dtel_int_set_sink {
#ifdef INT_EP_ENABLE
    apply(int_set_sink);
#endif
}

#ifdef INT_EP_ENABLE

action int_remove_header() {
    remove_header(int_header);
}

action int_sink_enable() {
    modify_field(int_metadata.sink, 1);
    modify_field(int_metadata.postcard_mode, 0);
}

action int_sink_disable(postcard_mode) {
    modify_field(int_metadata.sink, 0);
    modify_field(int_metadata.postcard_mode, postcard_mode);
}

#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma stage 4
#endif
table int_set_sink {
    // dscp,   int_header, action
    // *       valid       int_sink_enable
    // int     !valid      sink_set(0)_dscp_clear
    // default action : sink_disable
    reads{
        ipv4.diffserv           : ternary;
        int_header              : valid;
    }
    actions {
#ifdef INT_L45_DSCP_ENABLE
        int_sink_set_l45_dscp_clear_all;
        int_sink_set_l45_dscp_clear_2;
        int_sink_set_l45_dscp_clear_3;
        int_sink_set_l45_dscp_clear_4;
        int_sink_set_l45_dscp_clear_5;
        int_sink_set_l45_dscp_clear_6;
        int_sink_set_l45_dscp_clear_7;
#endif
        int_sink_enable;
        int_sink_disable;
    }
    default_action: int_sink_disable;
#ifdef INT_L45_DSCP_ENABLE
    size : 4;
#else
    size : 2;
#endif
}

/* hash functions to generate 16-bit digests for bloom filters*/
field_list dtel_upstream_flow_digest {
    dtel_flow_hash_field;
    int_header.rsvd2_digest;
}

field_list_calculation dtel_upstream_flow_digest_calc {
    input { dtel_upstream_flow_digest; }
    algorithm : crc_16_teledisk;
    output_width : DTEL_DIGEST_WIDTH;
}

// make path+latency digests to store in the ingress bloom filter
action make_upstream_digest() {
    modify_field_with_hash_based_offset(
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
        int_metadata.upstream_digest, 0,
#else
        int_header.rsvd2_digest, 0,
#endif
        dtel_upstream_flow_digest_calc, DTEL_DIGEST_RANGE);
}

#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma stage 4
#endif
#ifdef GENERIC_INT_LEAF_PROFILE
@pragma stage 3
#endif
table dtel_make_upstream_digest {
    actions { make_upstream_digest; }
    default_action : make_upstream_digest;
}

#endif // INT_EP_ENABLE

/*******************************************************************************
 INT sink ingress control block process_dtel_int_upstream_report
 Send upstream report if upstream flow state changes
 ******************************************************************************/

control process_dtel_int_upstream_report {
#ifdef INT_EP_ENABLE
    // this should be invoked after acl_mirror
    // favor existing acl mirror session over INT mirror
    // moving to before acls, pushes those tables down to
    // after bloom filters and int_upstream_report which uses more stages
    if (i2e_metadata.mirror_session_id == 0 and int_metadata.sink == 1) {
        apply(int_upstream_report);
    }
#endif // INT_EP_ENABLE
}

#ifdef INT_ENABLE

#ifdef INT_EP_ENABLE

field_list int_i2e_mirror_info {
    int_metadata.sink;
    i2e_metadata.mirror_session_id;
    i2e_metadata.ingress_tstamp;
    dtel_md.dscp_report;
    dtel_md.flow_hash;
}

// control plane shift_left user dscp (6b) by 2 bits for action param (8b)
// the 2 lsb bits are unused
action int_send_to_monitor_i2e (dscp_report) {
    // Send the upstream INT information to the pre-processor/monitor.
    // This is done via mirroring
    modify_field(i2e_metadata.mirror_session_id, dtel_md.mirror_session_id);
    modify_field(dtel_md.dscp_report, dscp_report);
    clone_ingress_pkt_to_egress(dtel_md.mirror_session_id, int_i2e_mirror_info);
}

// watchlist runs at source, int_upstream_report at sink
@pragma ignore_table_dependency int_watchlist
table int_upstream_report {
// priority is set by control plane higher dscp lower priority value
// digest, bfilter, TCP:
//// IF STFUL ENABLED (compile time at sink)
// 0,      xx,      x  : i2e (report all)
// 1,      1x,      x  : i2e (new flow)
// 1,      00,      x  : i2e (flow state change)
//// ELSE
//  ,        ,      x  : i2e (report all)
//// END
// x,      xx,      outer TCP & Flags : i2e
// x,      xx,      inner TCP & Flags : i2e

    reads {
#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
        int_metadata.digest_enb                : ternary;
        int_metadata.bfilter_output            : ternary;
#endif // DTEL_FLOW_STATE_TRACK_ENABLE

        tcp.valid                              : ternary;
        tcp.flags mask 0x7                     : ternary;
#ifdef DTEL_WATCH_INNER_ENABLE
        inner_tcp_info.flags mask 0x7          : ternary;
        inner_tcp_info.valid                   : ternary;
#endif
    }
    actions {
        int_send_to_monitor_i2e;
        nop;
    }
    default_action : nop;
    size : 65;  // to support all variations of 6 bit dscp as action param
}
#endif // INT_EP_ENABLE

/*******************************************************************************
 INT source ingress control block process_dtel_int_watchlist
 ******************************************************************************/

#ifdef INT_EP_ENABLE
control process_dtel_int_watchlist {
    if (int_metadata.sink == 0){
        // don't apply watchlist on INT packets at sink
        process_int_watchlist_(); // varies per encap
    }
}

// At source, samples if the packet will be monitored
// 100% means all flows, use int_not_watch for 0%
action int_watch_sample(digest_enb, config_session_id, sample_index){
    dtel_int_source_sample_alu.execute_stateful_alu(sample_index);
    modify_field(int_metadata.digest_enb, digest_enb);
    modify_field(int_metadata.config_session_id, config_session_id);
}

action int_not_watch() {
    modify_field(int_metadata.source, 0);
    modify_field(int_metadata.digest_enb, 0);
    modify_field(int_metadata.config_session_id, 0);
}

// int_watchlist always overwrites digest_enb if it hits.
// entry with priority 0 can be there just to disable INT source
// watchlist runs at source and int_upstream_report at sink
@pragma ignore_table_dependency int_upstream_report
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE) \
  || defined(MSDC_LEAF_DTEL_INT_PROFILE)
@pragma entries_with_ranges DTEL_FLOW_WATCHLIST_RANGE_ENTRIES
#endif
table int_watchlist {
    reads {
        DTEL_FLOW_WATCHLIST
#ifdef DTEL_WATCH_INNER_ENABLE
        DTEL_INNERFLOW_WATCHLIST
#endif
    }
    actions {
        int_watch_sample;
        int_not_watch;
    }
    size : DTEL_FLOW_WATCHLIST_TABLE_SIZE;
}

register dtel_int_sample_rate {
    width : 32;
    instance_count : 4096; // 1 sram block
}

blackbox stateful_alu dtel_int_source_sample_alu{
    reg: dtel_int_sample_rate;
    condition_lo:  dtel_md.flow_hash <= register_lo;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: int_metadata.source;
}
#endif // INT_EP_ENABLE

/*******************************************************************************
 INT transit ingress control block process_dtel_int_watchlist
 sets int_metadata.path_tracking_flow if parses an INT packet
 ******************************************************************************/

#ifdef INT_TRANSIT_ENABLE
control process_dtel_int_watchlist {
#if defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)
    if (valid(int_header)) {
        apply(transit_path_tracking_flow);
    }
#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE
}

#if defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)
action set_transit_path_tracking_flow() {
    modify_field(int_metadata.path_tracking_flow, 1);
}

table transit_path_tracking_flow {
    actions {
        set_transit_path_tracking_flow;
    }
    default_action : set_transit_path_tracking_flow;
}
#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE
#endif // INT_TRANSIT_ENABLE

/*******************************************************************************
 INT tables for egress pipeline
 If src/transit
    prepare INT switch data (eg. quantize and digest)
    insert INT data, update meta header
    if digest_enable, also insert/update digest encondings
    update outer encap
    if not-mirrored packet and queue_alert set, generate queue report through e2e
 If sink,
    removes INT headers and updates outer encap
    if going out of an edge port and is also source (1hop sink), set sink=1
    if local_latency changes or report all (digest_enb=0), or queue_alert=1
        or TCP flags are set
        clone e2e mirror for sink local report
 If sink i2e mirrored (upstream report)
    encap telemetry report header (via mirroring & tunnel)
    update report header bits in int_report_encap table
 If src/transit/sink e2e mirrored (local report)
    add switch local hdrs (but using its INT hop info headers)
    encap telemetry report header (via mirroring & tunnel)
    update report header bits in int_report_encap table
 ******************************************************************************/

/*******************************************************************************
 Egress control block process_dtel_local_report_ that is broken into two blocks
    At sink, this only runs for not mirrored packets
    if going out of an edge port and is also source (1hop sink), set sink=1
      this lets us treat the packet the same way as upstream INT packets
      This table also clears INT L45 DSCP if sink but not source
      (i.e. valid INT header present)
    At transit, if queue_alert is set initiate an e2e clone for queue report
    At sink, if digest is enabled (not report all) find if there is any flow
      state change
    At source/sink generate local report through e2e according to digest & queue report
 ******************************************************************************/

control process_dtel_int_edge_ports {
#ifdef INT_EP_ENABLE
    apply(int_edge_ports); // check if local 1hop sink
#endif // EP
}

control process_dtel_local_report2_ {
#if defined(INT_TRANSIT_ENABLE) && \
    defined(DTEL_QUEUE_REPORT_ENABLE)
    if (not pkt_is_mirrored and i2e_metadata.mirror_session_id == 0
        and dtel_md.queue_alert == 1) {
        apply(int_transit_qalert);
    }
#endif // TRANSIT && STLESS

#ifdef INT_EP_ENABLE

#if defined(DTEL_FLOW_STATE_TRACK_ENABLE)
    // do it only if sink is enabled and not report_all to not contaminate bloom filters
    if (not pkt_is_mirrored and i2e_metadata.mirror_session_id == 0
         and int_metadata.sink == 1 and int_metadata.digest_enb == 1) {
        process_dtel_detect_local_change();
    }
#endif // DTEL_FLOW_STATE_TRACK_ENABLE
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) && \
    defined(DTEL_DROP_FLOW_STATE_TRACK_ENABLE)
    else
#endif // DTEL_FLOW_STATE_TRACK_ENABLE && DTEL_DROP_FLOW_STATE_TRACK_ENABLE
#if defined(DTEL_DROP_FLOW_STATE_TRACK_ENABLE)
    if (pkt_is_mirrored and dtel_md.drop_flow_suppress == 1
        and ingress_metadata.drop_reason != 0) {
        process_dtel_detect_local_change();
    }
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
#endif // INT_EP_ENABLE
}

control process_dtel_local_report3_ {
#ifdef INT_EP_ENABLE
    // sink normal, do e2e clone
    // mirror_session_id can be overwritten by egress_acl later
    if (not pkt_is_mirrored and i2e_metadata.mirror_session_id == 0) {
        apply(int_sink_local_report);
    }
#endif // INT_EP_ENABLE
}

#ifdef INT_TRANSIT_ENABLE
field_list qalert_mirror_info {
    i2e_metadata.mirror_session_id;
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    ig_intr_md_for_tm.qid;
    eg_intr_md.deq_qdepth;
    i2e_metadata.ingress_tstamp;
    eg_intr_md_from_parser_aux.egress_global_tstamp;
    dtel_md.dscp_report;
    dtel_md.queue_alert;
    int_metadata.path_tracking_flow;
    dtel_md.flow_hash;
}

action do_int_transit_qalert_set_flow (dscp_report, path_tracking_flow){
    modify_field(int_metadata.path_tracking_flow, path_tracking_flow);
    // send the qalert information to the pre-processor/monitor, via mirroring
    modify_field(i2e_metadata.mirror_session_id, dtel_md.mirror_session_id);
    modify_field(dtel_md.dscp_report, dscp_report);
    clone_egress_pkt_to_egress(dtel_md.mirror_session_id, qalert_mirror_info);
}

// int_transit_qalert is not for mirrored packets but
// dtel_x_port_convert is only for mirrored
@pragma ignore_table_dependency dtel_ig_port_convert
@pragma ignore_table_dependency dtel_eg_port_convert
table int_transit_qalert {
    reads {
        int_header.valid           : exact;
    }
    actions{
        do_int_transit_qalert_set_flow;
    }
    default_action: do_int_transit_qalert_set_flow;
    size: 3;
}
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE

field_list int_e2e_mirror_info {
    i2e_metadata.mirror_session_id;
    int_metadata.sink;
    int_metadata.source;
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    ig_intr_md_for_tm.qid;
    eg_intr_md.deq_qdepth;
    i2e_metadata.ingress_tstamp;
    eg_intr_md_from_parser_aux.egress_global_tstamp;
    dtel_md.dscp_report;
    dtel_md.queue_alert;
    dtel_md.flow_hash;
}


action int_convert_word_to_byte() {
    // convert the word len to byte_cnt (relies on rsvd to be 0 before len)
#ifdef INT_OVER_L4_ENABLE
    shift_left(intl45_head_header.len, intl45_head_header.len, 2);
#endif
}

// control plane shift_left user dscp (6b) by 2 bits for action param (8b)
action int_send_to_monitor_e2e (dscp_report) {
    modify_field(dtel_md.dscp_report, dscp_report);
    // Send the upstream INT information to the pre-processor/monitor.
    // This is done via mirroring
    modify_field(i2e_metadata.mirror_session_id, dtel_md.mirror_session_id);
    clone_egress_pkt_to_egress(dtel_md.mirror_session_id, int_e2e_mirror_info);
}

// int_sink_local_report sets mirror_session_id for not mirrored packets
// but tunnel_encap_process_outer reads mirror_session_id for some mirrored packets
@pragma ignore_table_dependency tunnel_encap_process_outer
// int_sink_local_report only runs for not mirrored packets
// the following tables run only for mirrored packets
@pragma ignore_table_dependency int_report_encap
@pragma ignore_table_dependency dtel_ig_port_convert
@pragma ignore_table_dependency dtel_eg_port_convert
table int_sink_local_report {
// priority is set by control plane higher dscp lower priority value
// sink can be 0 for qalert on non-int packets
// TCP flag is only checked if sink=1 (INT from upstream or 1hop sink)
// sink, digest, bfilter, alert, TCP:
//// IF FLOW_STATE_TRACK ENABLED (compile time at sink)
// 1,    0,      xx,      x,     x  : report all
// 1,    1,      1x,      x,     x  : new flow
// 1,    1,      00,      x,     x  : flow change
//// ELSE
// 1,    x,      xx,      x,     x  : report all
//// ENDIF
//// IF QUEUE_REPORT ENABLED (compile time at sink)
// x,    x,      xx,      1,     x  : qalert
//// ENDIF
// 1,    x,      xx,      x,     inner & flag  : tcp
// 1,    x,      xx,      x,     outer & flag  : tcp
    reads {
        int_metadata.sink                      : ternary;
#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
        int_metadata.digest_enb                : ternary;
        dtel_md.bfilter_output                 : ternary;
#endif // DTEL_FLOW_STATE_TRACK_ENABLE

#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert                    : ternary;
#endif // DTEL_QUEUE_REPORT_ENABLE
        tcp.valid                              : ternary;
        tcp.flags mask 0x7                     : ternary;
#ifdef DTEL_WATCH_INNER_ENABLE
        inner_tcp_info.flags mask 0x7          : ternary;
        inner_tcp_info.valid                   : ternary;
#endif
    }
    actions {
        int_send_to_monitor_e2e;
        nop;
    }
    size : 65; // to support all variations of 6 bit dscp as action param
}

action set_int_sink() {
    modify_field(int_metadata.sink, 1);
}

#ifdef GENERIC_INT_LEAF_PROFILE
@pragma ternary 1
#endif
table int_edge_ports {
// int_md.source        int_md.sink     egress_port     action
// 1                    0               match           set_int_sink
//// IF POSTCARD ENABLED
// 1                    0               *               set_int_sink
//// ENDIF
//// IF INT ENABLED
// 0                    1               *               convert_word_to_byte
//// ENDIF
// default : nop
    reads {
        int_metadata.source    : exact;
        int_metadata.sink      : exact;
        eg_intr_md.egress_port : ternary;
    }
    actions {
        set_int_sink;
#ifdef INT_L45_DSCP_ENABLE
        int_convert_word_to_byte_l45_dscp_clear_all;
        int_convert_word_to_byte_l45_dscp_clear_2;
        int_convert_word_to_byte_l45_dscp_clear_3;
        int_convert_word_to_byte_l45_dscp_clear_4;
        int_convert_word_to_byte_l45_dscp_clear_5;
        int_convert_word_to_byte_l45_dscp_clear_6;
        int_convert_word_to_byte_l45_dscp_clear_7;
#else
        int_convert_word_to_byte;
#endif
        nop;
    }
    size: DTEL_INT_EDGE_PORTS_TABLE_SIZE;
}

#endif // INT_EP_ENABLE

/******************************************************************************
 control block process_dtel_insert_
 1) at transit updates INT meta header, stack and digest
 2) at sink, removes INT meta headers (data stack has been removed at egress
    parser) and updates INT encapsulation headers (ex: IP/UDP)
 3) at source adds INT meta header and stack
 4) at source adds INT flow state digest
 5) at source and transit updates INT encapsulation headers (ex: IP/UDP)
 6) at source or when INT is not added, sets or clears INT L45 DSCP
 ******************************************************************************/

control process_dtel_insert_ {
#ifdef INT_TRANSIT_ENABLE
    if (valid(int_header)){
        //  max_hop_cnt > total_hop_cnt
        if (int_header.max_hop_cnt != int_header.total_hop_cnt
                and int_header.e == 0){
            apply(int_transit);
#ifdef INT_DIGEST_ENABLE
            // assumes quantize_latency ran before
            apply(int_digest_encode);
#endif // INT_DIGEST_ENABLE
            apply(int_inst_0003);
            apply(int_inst_0407);
            process_int_outer_encap_(); // varies per encap
            int_hop_metadata_update();
        } else {
            apply(int_meta_header_update_end);
        }
    }
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE
    // INT sink
    // remove all INT-related headers
    if (int_metadata.sink == 1 and valid(int_header)){
        apply(int_terminate); // varies per encap
    }
    // INT source
    else if (int_metadata.sink == 0 and int_metadata.source == 1
             and eg_intr_md.deflection_flag == FALSE){
        apply(int_insert);
#ifdef INT_DIGEST_ENABLE
        if (int_metadata.digest_enb == 1){
            // assumes quantize_latency ran before (in local_report)
            apply(int_digest_insert);
        }
#endif // INT_DIGEST_ENABLE
        apply(int_inst_0003);
        apply(int_inst_0407);
        process_int_outer_encap_(); // varies per encap
        int_hop_metadata_update();
    }
#endif // INT_EP_ENABLE
}

// modify some of the inserted metadata headers
control int_hop_metadata_update {
    if (valid(int_port_ids_header)){
        apply(dtel_int_eg_port_convert);
        apply(dtel_int_ig_port_convert);
    }
}

action int_ig_port_convert(port) {
    modify_field(int_port_ids_header.ingress_port_id, port);
}

@pragma ignore_table_dependency int_report_encap
// Trade-off 1 TCAM with SRAM+hash bits
#if !defined(L3_HEAVY_INT_LEAF_PROFILE)
@pragma ternary 1
#endif
table dtel_int_ig_port_convert {
    reads {
        int_port_ids_header.ingress_port_id : exact;
    }
    actions {
        int_ig_port_convert;
        nop;
    }
    size: PORT_TABLE_SIZE;
}

action int_eg_port_convert(port) {
    modify_field(int_port_ids_header.egress_port_id, port);
}

@pragma ignore_table_dependency int_report_encap
// Trade-off 1 TCAM with SRAM+hash bits
#if !defined(L3_HEAVY_INT_LEAF_PROFILE)
@pragma ternary 1
#endif
table dtel_int_eg_port_convert {
    reads {
        int_port_ids_header.egress_port_id : exact;
    }
    actions {
        int_eg_port_convert;
        nop;
    }
    size: PORT_TABLE_SIZE;
}

// used at source and transit to update the digest
field_list dtel_int_digest_fields {
    dtel_md.quantized_latency;
    ingress_metadata.ingress_port;
    eg_intr_md.egress_port;
    int_header.rsvd2_digest;
}

field_list_calculation dtel_int_digest_calc {
    input { dtel_int_digest_fields; }
    algorithm : crc16;
    output_width : 16;
}

action update_int_digest() {
    modify_field(int_header.d, 1);
    modify_field_with_hash_based_offset(
        int_header.rsvd2_digest, 0, dtel_int_digest_calc, 65536);
}

action digest_debug_dummy_action(v){
    // bit_and(int_header.rsvd2_digest, int_header.rsvd2_digest, 0xffff);
    modify_field(dtel_md.quantized_latency, v);
}

#ifdef INT_TRANSIT_ENABLE

// add action update_int_digest_header at transit enable
// calculating hash requires a table hit so needs a matching field
table int_digest_encode {
    reads {
        int_header.d: exact;
    }
    actions {
        update_int_digest;
        nop;
    }
    default_action: nop;
    size : 3;
}

action adjust_insert_byte_cnt() {
    modify_field(int_metadata.int_hdr_word_len, int_header.ins_cnt);
}

// set default action to adjust_insert_byte_cnt if transit is enabled
table int_transit {
    actions {
        adjust_insert_byte_cnt;
        nop;
    }
    default_action: nop;
    size : 1;
}

action int_set_e_bit() {
    modify_field(int_header.e, 1);
}

// set default action to int_set_e_bit if transit enabled
table int_meta_header_update_end {
    actions {
        int_set_e_bit;
        nop;
    }
    default_action: nop;
    size : 1;
}
#endif  // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE

table int_digest_insert {
    actions {update_int_digest;}
    default_action : update_int_digest;
}

// assumes hop_cnt > 0
action add_int_header(hop_cnt, ins_cnt, ins_bitmap_0003, ins_bitmap_0407) {
    add_header(int_header);
    modify_field(int_header.ver, 0);
    modify_field(int_header.rep, 0);
    modify_field(int_header.c, 0);
    modify_field(int_header.e, 0);
    modify_field(int_header.d, 0);
    modify_field(int_header.rsvd1, 0);
    modify_field(int_header.ins_cnt, ins_cnt);
    modify_field(int_header.max_hop_cnt, hop_cnt);
    modify_field(int_header.total_hop_cnt, 1);
    modify_field(int_header.instruction_bitmap_0003, ins_bitmap_0003);
    modify_field(int_header.instruction_bitmap_0407, ins_bitmap_0407);
    modify_field(int_header.instruction_bitmap_0811, 0); // not supported
    modify_field(int_header.instruction_bitmap_1215, 0); // not supported
    modify_field(int_header.rsvd2_digest, 0);
}

// INT E2E and MoD are mutually exclusive
@pragma ignore_table_dependency mirror_on_drop_encap
table int_insert {
    reads {
        int_metadata.config_session_id : exact;
    }
    actions {
        add_int_header;
    }
    default_action: add_int_header(8, 5, 0xd, 0xc);
    size : DTEL_CONFIG_SESSIONS;
}

#endif  // INT_EP_ENABLE

/*******************************************************************************
 control block process_dtel_report_encap_
 1) updates the outer encapsulation for INT i2e, e2e
 2) updates the outer encapsulation for queue report packets that are not dropped
 ******************************************************************************/

control process_dtel_report_encap_ {
#if defined(INT_EP_ENABLE) || \
    (defined(INT_TRANSIT_ENABLE) && defined(DTEL_QUEUE_REPORT_ENABLE))
    apply(int_report_encap);
#endif // TRANSIT && QUEUE_REPORT || EP
}


action int_update_outer_encap(insert_byte_cnt, udp_port, flags){
    modify_field(dtel_report_header.merged_fields, flags);
    modify_field(udp.dstPort, udp_port);
    add_to_field(udp.length_, insert_byte_cnt);
    add_to_field(ipv4.totalLen, insert_byte_cnt);
    modify_field(ipv4.diffserv, dtel_md.dscp_report, 0xfc);
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    modify_field(dtel_md.drop_flow_suppress, 0);
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

action int_e2e(insert_byte_cnt, switch_id, udp_port, flags){
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, switch_id);
    int_set_header_1();
    int_set_header_2();
    int_set_header_3();
    int_set_header_5();
    int_update_outer_encap(insert_byte_cnt, udp_port, flags);
}

#ifdef INT_TRANSIT_ENABLE

// report encap is only for mirror copy,
// dtel_int_x_port_convert is for regular packets
@pragma ignore_table_dependency dtel_int_ig_port_convert
@pragma ignore_table_dependency dtel_int_eg_port_convert
@pragma ignore_table_dependency int_inst_0407
@pragma ignore_table_dependency int_inst_0003
table int_report_encap {
// p_t_flow, qalert
// 0,        0       : nop
// 1,        0       : nop, INT transit only generates report on qalert or mod
// 0,        1       : int_e2e (path_tracking_flow=0, congested_queue=1)
// 1,        1       : int_e2e (path_tracking_flow=1, congested_queue=1)
    reads {
        int_metadata.path_tracking_flow  : exact;
        dtel_md.queue_alert         : exact;
    }
    actions {
        int_e2e;
        nop;
    }
    size : 4;
}
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE

// int_report_encap is for mirrored packets others are not
@pragma ignore_table_dependency int_sink_local_report
@pragma ignore_table_dependency dtel_int_ig_port_convert
@pragma ignore_table_dependency dtel_int_eg_port_convert
@pragma ignore_table_dependency int_switch_id
@pragma ignore_table_dependency int_inst_0407
@pragma ignore_table_dependency int_inst_0003
table int_report_encap {
// priority is not important
// sink, src, clone, qalert
// 1,    0,   1      0      : int_update_outer_encap (p_t_flow=1, con_queue=0)
// 0,    0,   3      1      : int_e2e (path_tracking_flow=0, congested_queue=1)
// 0,    1,   3      1      : int_e2e (path_tracking_flow=1, congested_queue=1)
// 1,    x,   3      0      : int_e2e (path_tracking_flow=1, congested_queue=0)
// 1,    x,   3      1      : int_e2e (path_tracking_flow=1, congested_queue=1)
    reads {
        int_metadata.sink                    : ternary;
        int_metadata.source                  : ternary;
        eg_intr_md_from_parser_aux.clone_src : exact;
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert                  : exact;
#endif // DTEL_QUEUE_REPORT_ENABLE
    }
    actions {
        int_update_outer_encap;
        int_e2e;
        nop;
    }
    size : 8;
}

#endif // INT_EP_ENABLE

/*******************************************************************************
 Tables and actions for INT metadata update, used at egress
 ******************************************************************************/

/*
 * INT instruction decode
 * 4 tables, each look at 4 bits of insturction
 * BOS table to set the bottom-of-stack bit on the last INT data
 */

/* Instr Bit 0: switch id */
action int_set_header_0(switch_id) {
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, switch_id);
}

/* Instr Bit 1: ingress and egress port ids */
action int_set_header_1() {
    add_header(int_port_ids_header);
    modify_field(
        int_port_ids_header.ingress_port_id, ingress_metadata.ingress_port);
    modify_field(
        int_port_ids_header.egress_port_id, egress_metadata.egress_port);
}

/* Instr Bit 2: hop latency */
action int_set_header_2() {
    //add_header(int_hop_latency_header);
    // hop_latency: timedelta in nanoseconds
    //modify_field(int_hop_latency_header.hop_latency,
    //             eg_intr_md.deq_timedelta);
}

/* Instr Bit 3: qid and queue occupancy */
action int_set_header_3() {
    add_header(int_q_occupancy_header);
    //modify_field(int_q_occupancy_header.rsvd, 0);
    modify_field(int_q_occupancy_header.qid, ig_intr_md_for_tm.qid);
    modify_field(int_q_occupancy_header.q_occupancy0,
                 eg_intr_md.deq_qdepth);
}

/* Instr Bit 4: ingress tstamp */
action int_set_header_4() {
    add_header(int_ingress_tstamp_header);
    modify_field(int_ingress_tstamp_header.ingress_tstamp,
                 i2e_metadata.ingress_tstamp);
}

/* Instr Bit 5: egress timestamp */
action int_set_header_5() {
    add_header(int_egress_tstamp_header);
    modify_field(int_egress_tstamp_header.egress_tstamp,
                 eg_intr_md_from_parser_aux.egress_global_tstamp);
}

/* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
/* Each bit set indicates that corresponding INT header should be added */
action int_set_header_0003_i0() {
}
action int_set_header_0003_i1() {
    int_set_header_3();
}
action int_set_header_0003_i2() {
    int_set_header_2();
}
action int_set_header_0003_i3() {
    int_set_header_3();
    int_set_header_2();
}
action int_set_header_0003_i4() {
    int_set_header_1();
}
action int_set_header_0003_i5() {
    int_set_header_3();
    int_set_header_1();
}
action int_set_header_0003_i6() {
    int_set_header_2();
    int_set_header_1();
}
action int_set_header_0003_i7() {
    int_set_header_3();
    int_set_header_2();
    int_set_header_1();
}
action int_set_header_0003_i8(switch_id) {
    int_set_header_0(switch_id);
}
action int_set_header_0003_i9(switch_id) {
    int_set_header_3();
    int_set_header_0(switch_id);
}
action int_set_header_0003_i10(switch_id) {
    int_set_header_2();
    int_set_header_0(switch_id);
}
action int_set_header_0003_i11(switch_id) {
    int_set_header_3();
    int_set_header_2();
    int_set_header_0(switch_id);
}
action int_set_header_0003_i12(switch_id) {
    int_set_header_1();
    int_set_header_0(switch_id);
}
action int_set_header_0003_i13(switch_id) {
    int_set_header_3();
    int_set_header_1();
    int_set_header_0(switch_id);
}
action int_set_header_0003_i14(switch_id) {
    int_set_header_2();
    int_set_header_1();
    int_set_header_0(switch_id);
}
action int_set_header_0003_i15(switch_id) {
    int_set_header_3();
    int_set_header_2();
    int_set_header_1();
    int_set_header_0(switch_id);
}

/* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
// only action 4-5 is supported now
action int_set_header_0407_i4() {
    int_set_header_5();
    int_header_update();
}
action int_set_header_0407_i8() {
    int_set_header_4();
    int_header_update();
}
action int_set_header_0407_i12() {
    int_set_header_4();
    int_set_header_5();
    int_header_update();
}

@pragma ternary 1
@pragma ignore_table_dependency int_report_encap
table int_inst_0003 {
    reads {
        int_header.instruction_bitmap_0003 : exact;
    }
    actions {
        int_set_header_0003_i0;
        int_set_header_0003_i1;
        int_set_header_0003_i2;
        int_set_header_0003_i3;
        int_set_header_0003_i4;
        int_set_header_0003_i5;
        int_set_header_0003_i6;
        int_set_header_0003_i7;
        int_set_header_0003_i8;
        int_set_header_0003_i9;
        int_set_header_0003_i10;
        int_set_header_0003_i11;
        int_set_header_0003_i12;
        int_set_header_0003_i13;
        int_set_header_0003_i14;
        int_set_header_0003_i15;
    }
    default_action: int_set_header_0003_i0;
    size : 17;
}

@pragma ignore_table_dependency int_report_encap
table int_inst_0407 {
    reads {
        int_header.instruction_bitmap_0407 : ternary;
    }
    actions {
        int_set_header_0407_i4;
		int_set_header_0407_i8;
        int_set_header_0407_i12;
        int_header_update;
        nop;
    }
    default_action: nop;
    size : 17;
}

// update the INT metadata header
action int_header_update() {
#ifdef INT_TRANSIT_ENABLE
    add_to_field(int_header.total_hop_cnt, 1);
    // insert_byte_cnt = 4*int_hdr_word_len
    shift_left(int_metadata.insert_byte_cnt, int_metadata.int_hdr_word_len, 2);
#endif //INT_TRANSIT_ENABLE

}

/*******************************************************************************
 Bloom Filters for detecting path flow state changes at ingress, INT EP only
 ******************************************************************************/

#if defined(INT_EP_ENABLE) && defined(DTEL_FLOW_STATE_TRACK_ENABLE)

register dtel_ig_bfilter_reg_1{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_ig_bfilter_1;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}
register dtel_ig_bfilter_reg_2{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_ig_bfilter_2;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}
register dtel_ig_bfilter_reg_3{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_ig_bfilter_3;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}
register dtel_ig_bfilter_reg_4{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_ig_bfilter_4;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}

blackbox stateful_alu dtel_ig_bfilter_alu_1{
    reg: dtel_ig_bfilter_reg_1;

    // encode 'old==0' into high bit, 'new==old' into low bit of alu_hi
    condition_hi: register_lo == 0;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    condition_lo: register_lo == int_metadata.upstream_digest;
#else
    condition_lo: register_lo == int_header.rsvd2_digest;
#endif
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    update_lo_1_value: int_metadata.upstream_digest;
#else
    update_lo_1_value: int_header.rsvd2_digest;
#endif

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

blackbox stateful_alu dtel_ig_bfilter_alu_2{
    reg: dtel_ig_bfilter_reg_2;

    condition_hi: register_lo == 0;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    condition_lo: register_lo == int_metadata.upstream_digest;
#else
    condition_lo: register_lo == int_header.rsvd2_digest;
#endif
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    update_lo_1_value: int_metadata.upstream_digest;
#else
    update_lo_1_value: int_header.rsvd2_digest;
#endif

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

blackbox stateful_alu dtel_ig_bfilter_alu_3{
    reg: dtel_ig_bfilter_reg_3;

    condition_hi: register_lo == 0;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    condition_lo: register_lo == int_metadata.upstream_digest;
#else
    condition_lo: register_lo == int_header.rsvd2_digest;
#endif
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    update_lo_1_value: int_metadata.upstream_digest;
#else
    update_lo_1_value: int_header.rsvd2_digest;
#endif

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

blackbox stateful_alu dtel_ig_bfilter_alu_4{
    reg: dtel_ig_bfilter_reg_4;

    condition_hi: register_lo == 0;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    condition_lo: register_lo == int_metadata.upstream_digest;
#else
    condition_lo: register_lo == int_header.rsvd2_digest;
#endif
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
#ifdef INT_L4_CHECKSUM_UPDATE_ENABLE
    update_lo_1_value: int_metadata.upstream_digest;
#else
    update_lo_1_value: int_header.rsvd2_digest;
#endif

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

/*  actions to execute the filters */
action run_dtel_ig_bfilter_1() {
    dtel_ig_bfilter_alu_1.execute_stateful_alu_from_hash(dtel_hash_1);
}
action run_dtel_ig_bfilter_2() {
    dtel_ig_bfilter_alu_2.execute_stateful_alu_from_hash(dtel_hash_2);
}
action run_dtel_ig_bfilter_3() {
    dtel_ig_bfilter_alu_3.execute_stateful_alu_from_hash(dtel_hash_3);
}
action run_dtel_ig_bfilter_4() {
    dtel_ig_bfilter_alu_4.execute_stateful_alu_from_hash(dtel_hash_4);
}

/* separate tables to run the bloom filters. */
// hash calclation action must be a hit action or only action
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 5
#endif
table dtel_ig_bfilter_1 {
    actions {run_dtel_ig_bfilter_1;}
    default_action : run_dtel_ig_bfilter_1;
}
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 5
#endif
table dtel_ig_bfilter_2 {
    actions {run_dtel_ig_bfilter_2;}
    default_action : run_dtel_ig_bfilter_2;
}
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 5
#endif
table dtel_ig_bfilter_3 {
    actions {run_dtel_ig_bfilter_3;}
    default_action : run_dtel_ig_bfilter_3;
}
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 5
#endif
table dtel_ig_bfilter_4 {
    actions {run_dtel_ig_bfilter_4;}
    default_action : run_dtel_ig_bfilter_4;
}

control process_dtel_upstream_change {
    // Use bloom filter to detect any change in path or latency
    // If there is need to report,
    apply(dtel_ig_bfilter_1);
#ifndef DTEL_BF_1_WAY_HASH_ENABLE
    apply(dtel_ig_bfilter_2);
#ifndef DTEL_BF_2_WAY_HASH_ENABLE
    apply(dtel_ig_bfilter_3);
#ifndef DTEL_BF_3_WAY_HASH_ENABLE
    apply(dtel_ig_bfilter_4);
#endif // !DTEL_BF_3_WAY_HASH_ENABLE
#endif // !DTEL_BF_2_WAY_HASH_ENABLE
#endif // !DTEL_BF_1_WAY_HASH_ENABLE
}

#endif // INT_EP_ENABLE && DTEL_FLOW_STATE_TRACK_ENABLE
#endif // INT_ENABLE
