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
/*
 * Postcard processing
 * At ingress apply watchlist
 * At egress if report all / any flow changes / queue report for not dropped packets
 *   generate an e2e clone
 * add switch local headers (poscart header) and update telemetry report header
 */

header_type postcard_metadata_t {
    fields {
        report       : 1; // set if watchlist is hit
        suppress_enb : 1; // set if must track flow state changes (!report_all)
    }
}

#ifdef Q0_PROFILE
@pragma pa_no_overlay ingress postcard_md.suppress_enb
@pragma pa_mutually_exclusive egress postcard_header.switch_id mirror_on_drop_header.switch_id
#endif
metadata postcard_metadata_t postcard_md;

#ifdef POSTCARD_ENABLE

/*******************************************************************************
 Postcard ingress control block process_dtel_postcard_watchlist
 apply postcard wathclist to all traffic
*******************************************************************************/
control process_dtel_postcard_watchlist {
    apply(postcard_watchlist);
}

// watches if the packet will be monitored
// 100% fo all flows, use postcard_not_watch for 0%
action postcard_watch_sample(suppress_enb, sample_index){
    dtel_postcard_sample_alu.execute_stateful_alu(
        sample_index);
    modify_field(postcard_md.suppress_enb, suppress_enb);
}

#ifdef DTEL_ACL_SEPARATE_STAGES
action postcard_watch_sample_v6(suppress_enb, sample_index){
    dtel_postcard_sample_v6_alu.execute_stateful_alu(
        sample_index);
    modify_field(postcard_md.suppress_enb, suppress_enb);
}
#endif /* DTEL_ACL_SEPARATE_STAGES */

action postcard_not_watch() {
    modify_field(postcard_md.report, 0);
    modify_field(postcard_md.suppress_enb, 0);
}

table postcard_watchlist {
    reads {
        DTEL_FLOW_WATCHLIST
#ifdef DTEL_WATCH_INNER_ENABLE
        DTEL_INNERFLOW_WATCHLIST
#endif
    }
    actions {
        postcard_watch_sample;
        postcard_not_watch;
    }
    size: DTEL_FLOW_WATCHLIST_TABLE_SIZE;
}

/*******************************************************************************
 Postcard egress control block process_dtel_local_report2_
   detect flow changes if not report_all
   generate report for report_all / flow state changes / queue report
*******************************************************************************/
control process_dtel_local_report2_ {
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE)
    // do it only if not report_all to not contaminate bloom filters
    if (not pkt_is_mirrored and i2e_metadata.mirror_session_id == 0
        and postcard_md.report == 1 and postcard_md.suppress_enb == 1) {
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
}

control process_dtel_local_report3_ {
    if (not pkt_is_mirrored and i2e_metadata.mirror_session_id == 0) {
        apply(dtel_postcard_e2e);
    }
}

field_list postcard_mirror_info {
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    i2e_metadata.mirror_session_id;
    i2e_metadata.ingress_tstamp;
    ig_intr_md_for_tm.qid;
    eg_intr_md.deq_qdepth;
    eg_intr_md_from_parser_aux.egress_global_tstamp;
    postcard_md.report;
    dtel_md.dscp_report;
    dtel_md.queue_alert;
    dtel_md.flow_hash;
}

// control plane shift_left user dscp (6b) by 2 bits for action param (8b)
action postcard_e2e(dscp_report) {
    modify_field(i2e_metadata.mirror_session_id,
                 dtel_md.mirror_session_id);
    modify_field(dtel_md.dscp_report, dscp_report);
    clone_egress_pkt_to_egress(dtel_md.mirror_session_id,
                               postcard_mirror_info);
}

// dtel_postcard_e2e shall not run for mirrored packets
// mirror, dtel_postcard_insert and dtel_postcard_encap only run
// for mirrored packets (compiler has hard time to find the independence)
@pragma ignore_table_dependency mirror
@pragma ignore_table_dependency dtel_postcard_insert
@pragma ignore_table_dependency tunnel_encap_process_outer
@pragma ignore_table_dependency dtel_ig_port_convert
@pragma ignore_table_dependency dtel_eg_port_convert
table dtel_postcard_e2e {
// priority is important
// report, enb, bfilter, alert, TCP:
//// IF FLOW_STATE_TRACK ENABLED
// 1,      0,   xx,      x,     x  : report all
// 1,      1,   1x,      x,     x  : new flow
// 1,      1,   00,      x,     x  : flow change
//// ELSE
// 1,       ,     ,       ,     x  : postcard
//// ENDIF
//// IF QUEUE_REPORT ENABLED
// x,       ,     ,      1,     x  : qalert
//// ENDIF
// 1,      x,   xx,      x,     inner & flag  : tcp
// 1,      x,   xx,      x,     outer & flag  : tcp
    reads{
        postcard_md.report                 : ternary;
#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
        postcard_md.suppress_enb           : ternary;
        dtel_md.bfilter_output             : ternary;
#endif
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert                : ternary;
#endif
        tcp.valid                          : ternary;
        tcp.flags mask 0x7                 : ternary;
#ifdef DTEL_WATCH_INNER_ENABLE
        inner_tcp_info.flags mask 0x7      : ternary;
        inner_tcp_info.valid               : ternary;
#endif
    }
    actions {
        postcard_e2e;
        nop;
    }
    default_action : nop;
    size: 16;
}


/*******************************************************************************
 Postcard egress control block process_dtel_report_encap_
 Adds postcard header as local switch telemetry information
 Updates telemetry report header fields
*******************************************************************************/
control process_dtel_report_encap_ {
    apply(dtel_postcard_insert);
}

action postcard_outer_update(udp_port, flags) {
    modify_field(dtel_report_header.merged_fields, flags);
    modify_field(udp.dstPort, udp_port);
    add_to_field(udp.length_, 16); // postcard header size is 16B
    add_to_field(ipv4.totalLen, 16); // postcard header size is 16B
    modify_field(ipv4.diffserv, dtel_md.dscp_report, 0xfc);
}

action postcard_insert_common(switch_id) {
    add_header(postcard_header);
    modify_field(postcard_header.switch_id, switch_id);
    modify_field(postcard_header.ingress_port, ingress_metadata.ingress_port);
    modify_field(postcard_header.egress_port, egress_metadata.egress_port);
    modify_field(postcard_header.queue_id, ig_intr_md_for_tm.qid);
    modify_field(postcard_header.queue_depth, eg_intr_md.deq_qdepth);
    modify_field(postcard_header.egress_tstamp,
                 eg_intr_md_from_parser_aux.egress_global_tstamp);
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    modify_field(dtel_md.drop_flow_suppress, 0);
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

action postcard_insert(switch_id, udp_port, flags){
    postcard_insert_common(switch_id);
    postcard_outer_update(udp_port, flags);
}

// dtel_postcard_insert runs on not mirrored packets, dtel_postcard_e2e runs for mirrored ones
@pragma ignore_table_dependency dtel_postcard_e2e
table dtel_postcard_insert {
// report, qalert:
// 0     , 0     : nop
// 0     , 1     : postcard_insert (path_tracking_flow=0, congested_queue=1)
// 1     , 0     : postcard_insert (path_tracking_flow=1, congested_queue=0)
// 1     , 1     : postcard_insert (path_tracking_flow=1, congested_queue=1)
    reads {
        postcard_md.report  : exact;
        dtel_md.queue_alert : exact;
    }
    actions {
        postcard_insert;
        nop;
    }
    size: 5;
}

register dtel_postcard_sample_rate {
    width : 32;
    instance_count : 4096; // 1 sram block
}

blackbox stateful_alu dtel_postcard_sample_alu{
    reg: dtel_postcard_sample_rate;
    condition_lo:  dtel_md.flow_hash <= register_lo;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: postcard_md.report;
}

#ifdef DTEL_ACL_SEPARATE_STAGES
register dtel_postcard_sample_rate_v6 {
    width : 32;
    instance_count : 4096; // 1 sram block
}

blackbox stateful_alu dtel_postcard_sample_v6_alu{
    reg: dtel_postcard_sample_rate_v6;
    condition_lo:  dtel_md.flow_hash <= register_lo;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: postcard_md.report;
}
#endif /* DTEL_ACL_SEPARATE_STAGES */

#endif // POSTCARD_ENABLE
