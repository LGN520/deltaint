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
 * DTel code shared by INT, Postcard, Mirror on Drop (Drop Report) and Queue Report
 */

#ifdef DTEL_BF_1_WAY_HASH_ENABLE
#define DTEL_FLOW_HASH_WIDTH 16
#define DTEL_FLOW_HASH_RANGE 65536 // 2^16
#else
#define DTEL_FLOW_HASH_WIDTH 32
#define DTEL_FLOW_HASH_RANGE 4294967296 // 2^32
#endif /* DTEL_BF_1_WAY_HASH_ENABLE */
#define DTEL_DIGEST_WIDTH    16         // size of each cell
#define DTEL_DIGEST_RANGE    65536      // 2^16

#ifdef FLOW_WATCHLIST_INDIRECT_RANGE_MATCH
#define DTEL_FLOW_WATCHLIST \
        ethernet.etherType              : ternary; \
        ipv4.valid                      : ternary; \
        ipv4.srcAddr                    : ternary; \
        ipv4.dstAddr                    : ternary; \
        ipv4.protocol                   : ternary; \
        ipv4.diffserv mask 0xFC         : ternary; \
        acl_metadata.ingress_src_port_range_id : ternary; \
        acl_metadata.ingress_dst_port_range_id : ternary;
#else
#define DTEL_FLOW_WATCHLIST \
        ethernet.etherType              : ternary; \
        ipv4.valid                      : ternary; \
        ipv4.srcAddr                    : ternary; \
        ipv4.dstAddr                    : ternary; \
        ipv4.protocol                   : ternary; \
        ipv4.diffserv mask 0xFC         : ternary; \
        l3_metadata.lkp_l4_sport        : range; \
        l3_metadata.lkp_l4_dport        : range;
#endif

#define DTEL_INNERFLOW_WATCHLIST \
        tunnel_metadata.tunnel_vni      : ternary; \
        inner_ethernet.etherType        : ternary; \
        inner_ipv4.valid                : ternary; \
        inner_ipv4.srcAddr              : ternary; \
        inner_ipv4.dstAddr              : ternary; \
        inner_ipv4.protocol             : ternary; \
        inner_l4_ports.srcPort          : range; \
        inner_l4_ports.dstPort          : range;

header_type dtel_metadata_t {
    fields {
        // flow hash for mirror load balancing and flow state change detection
        flow_hash           : DTEL_FLOW_HASH_WIDTH;

        // mirror id for mirror load balancing
        mirror_session_id   : 10;

        // quantized latency for flow state change detection
        quantized_latency   : 32;

        // local digest at egress pipe for flow state change detection
        local_digest        : DTEL_DIGEST_WIDTH;

        // encodes 2 bit information for flow state change detection
        // MSB = 1 if old == 0 in any filter --> new flow.
        // LSB = 1 if new == old in any filter --> no value change
        // suppress report if bfilter_output == 1 (MSB == 0 and LSB == 1).
        bfilter_output      : 2;

        // indicates if queue latency and/or depth exceed thresholds
        queue_alert         : 1;

        // common index for port-qid tuple for queue report tables
        queue_alert_index   : 10;

        // for regular egress indicates if queue latency and/or depth changed
        queue_change        : 1;

        // is 1 if we can still send more queue_report packets that have not changes
        queue_report_quota  : 1;

        // True if hit Mirror on Drop watchlist with watch action
        // higher bit is set if DoD is requested in the watchlist
        mod_watchlist_hit   : 2;

        // True if queue-based deflect on drop is enabled
        queue_dod_enable    : 1;

        // At ingress and egress for not mirrored packets, true if drop reports
        // are to be suppressed on a per flow basis (from drop watchlist). At
        // egress for mirrored packets, after mirror_on_drop_encap table, value
        // indicates whether this specific report packet should be dropped.
        drop_flow_suppress  : 1;

        // Upper 6 bits represent the dscp of report packets
        // Lower 2 bits can be used to pass control from ingress to egress
        dscp_report         : 8;
    }
}
#if defined(INT_OVER_L4_ENABLE) && defined(INT_EP_ENABLE) && \
    !defined(INT_L4_CHECKSUM_UPDATE_ENABLE)
// at egress local_digest is used at sink, int_header is only valid at source
@pragma pa_alias egress dtel_md.local_digest int_header.rsvd2_digest
#endif // INT_OVER_L4_ENABLE && INT_EP_ENABLE && !INT_L4_CHECKSUM_UPDATE_ENABLE

// queue_alert is input to SALU, put it solitary and 8bit container to save hash bits
@pragma pa_solitary egress dtel_md.queue_alert
#if !defined(L3_HEAVY_INT_LEAF_PROFILE) && !defined(GENERIC_INT_LEAF_PROFILE) \
    && !defined(L3_HEAVY_INT_SPINE_PROFILE) \
    && !defined(GENERIC_INT_SPINE_PROFILE)
@pragma pa_container_size egress dtel_md.queue_alert 8
#endif
// Workaround for COMPILER-844
#ifdef INT_EP_ENABLE
@pragma pa_solitary ingress dtel_md.mirror_session_id
#endif
#if defined(ENT_FIN_POSTCARD_PROFILE)
@pragma pa_no_overlay egress dtel_md.dscp_report
#endif
#ifdef DTEL_COMMON_HASH_ENABLE
@pragma pa_alias ingress hash_metadata.hash1 dtel_md.flow_hash
@pragma pa_no_init ingress dtel_md.flow_hash
#endif
#if defined(Q0_PROFILE)
@pragma pa_container_size ingress dtel_md.drop_flow_suppress 16
@pragma pa_container_size egress dtel_md.drop_flow_suppress 16
#endif
#if defined(M0_PROFILE)
@pragma pa_no_init egress dtel_md.dscp_report
#endif
metadata dtel_metadata_t dtel_md;

/*******************************************************************************
 Control blocks exposed to switch.p4
 ******************************************************************************/
control process_dtel_ingress_prepare {
#ifndef DTEL_COMMON_HASH_ENABLE
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) || defined(DTEL_REPORT_ENABLE)
    apply(dtel_flow_hash_outer);
#endif // DTEL_FLOW_STATE_TRACK_ENABLE || DTEL_REPORT_ENABLE
#endif /* !DTEL_COMMON_HASH_ENABLE */
}

control process_dtel_watchlist {
#ifdef DTEL_REPORT_LB_ENABLE
#if !defined(Q0_PROFILE)
    apply(dtel_mirror_session);
#endif
#endif /* DTEL_REPORT_LB_ENABLE */

#ifdef DTEL_ACL_ENABLE
    process_dtel_acl();
#else /* !DTEL_ACL_ENABLE */
#ifdef POSTCARD_ENABLE
    process_dtel_postcard_watchlist();
#endif
#if defined(INT_EP_ENABLE) || defined(INT_TRANSIT_ENABLE)
#ifndef L3_HEAVY_INT_LEAF_PROFILE
    process_dtel_int_watchlist();
#endif
#endif /* INT_EP_ENABLE || INT_TRANSIT_ENABLE */
#endif /* DTEL_ACL_ENABLE */
}

control process_dtel_mod_watchlist {
#if defined(DTEL_DROP_REPORT_ENABLE) && !defined(DTEL_ACL_ENABLE)
    apply(mirror_on_drop_watchlist);
#endif // DTEL_DROP_REPORT_ENABLE && !DTEL_ACL_ENABLE
}

control process_dtel_queue_watchlist {
// must be after egress port and qid are resolved

#ifdef DTEL_QUEUE_REPORT_ENABLE
    // must be after mod watchlist if it sets dod bit to false
    apply(deflect_on_drop_queue_config);
#endif // DTEL_QUEUE_REPORT_ENABLE
}

control process_dtel_prepare_egress {
#if defined(DTEL_QUEUE_REPORT_ENABLE) || \
    defined(DTEL_FLOW_STATE_TRACK_ENABLE) || \
    defined(INT_DIGEST_ENABLE)
#ifndef CALCULATE_LATENCY_OPTIMIZATION_ENABLE
    apply(dtel_calculate_latency);
#endif
#ifdef DTEL_QUEUE_REPORT_ENABLE
    apply(dtel_queue_alert);
#else
    // if queue_report, mask_latency piggy backs on dtel_queue_alert table
    apply(dtel_mask_latency);
#endif // DTEL_QUEUE_REPORT_ENABLE
#endif // QUEUE_REPORT || FLOW_STATE_TRACK || DIGEST

}

control process_dtel_deflect_on_drop {
#ifdef DTEL_QUEUE_REPORT_ENABLE
   if (dtel_md.queue_dod_enable == 1){
      // only update quota if dod is because of queue_report
      apply(dtel_queue_report_dod_quota);
   }
#endif
#ifdef INT_OVER_L4_ENABLE
   process_dtel_deflect_on_drop_();
#endif
}

control process_dtel_queue_alert_update {
#ifdef DTEL_QUEUE_REPORT_ENABLE
    apply(dtel_queue_alert_update);
#endif
}

control process_dtel_local_report2 {
    // run only for not mirrored packets
    // separated from report1 to break the table dependency chain
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE)
#ifndef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    if (not pkt_is_mirrored) {
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        apply(dtel_make_local_digest);
#ifndef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    }
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
#endif // DTEL_FLOW_STATE_TRACK_ENABLE

    // defined in dtel_int.p4 and dtel_postcard.p4
#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
    process_dtel_local_report2_();
#endif // INT or POSTCARD
}

control process_dtel_local_report1 {
    // run only for not mirrored packets
#ifdef DTEL_QUEUE_REPORT_ENABLE
    if (dtel_md.queue_alert == 1){
        apply(dtel_queue_change);
    }
    apply(dtel_queue_report_quota);
#endif

#ifdef INT_EP_ENABLE
#ifndef L3_HEAVY_INT_LEAF_PROFILE
    process_dtel_int_edge_ports();
#endif
#endif
}

control process_dtel_local_report3 {
#if defined(INT_EP_ENABLE) || defined(POSTCARD_ENABLE)
    process_dtel_local_report3_();
#endif // INT_EP_ENABLE || POSTCARD_ENABLE
}

control process_dtel_drop_suppress_prepare {
#if defined(DTEL_DROP_FLOW_STATE_TRACK_ENABLE)
    apply(dtel_drop_suppress_prepare);
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

control process_dtel_insert {
// run only for not mirrored packets
#if defined(INT_ENABLE)
    // defined in dtel_int.p4
    process_dtel_insert_();
#endif
}

control process_dtel_port_convert {
// run only for mirrored packets
// convert h/w port to front panel port for DTel mirror packets
// ifdefs are to apply the code only when we are sure that
// the mirror copy is for dtel
#if defined(INT_EP_ENABLE) || defined(POSTCARD_ENABLE) || \
    defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)

#ifdef INT_EP_ENABLE
#define DTEL_VALID_FLOW (int_metadata.sink == 1)
#endif
#ifdef POSTCARD_ENABLE
#define DTEL_VALID_FLOW (postcard_md.report == 1)
#endif
#ifdef DTEL_DROP_REPORT_ENABLE
#define DTEL_VALID_MOD (ingress_metadata.drop_reason != 0)
#endif
#ifdef DTEL_QUEUE_REPORT_ENABLE
#define DTEL_VALID_QUEUE (dtel_md.queue_alert == 1)
#endif

    if (
#ifdef DTEL_VALID_FLOW
        DTEL_VALID_FLOW
#endif // DTEL_VALID_FLOW

#ifdef DTEL_VALID_MOD
#ifdef DTEL_VALID_FLOW
        or
#endif
        DTEL_VALID_MOD
#endif // DTEL_VALID_MOD

#ifdef DTEL_VALID_QUEUE
#if defined(DTEL_VALID_FLOW) || defined(DTEL_VALID_MOD)
        or
#endif
        DTEL_VALID_QUEUE
#endif // DTEL_VALID_QUEUE
){
        apply(dtel_ig_port_convert);
        apply(dtel_eg_port_convert);
    }
#endif // INT_EP_ENABLE || POSTCARD_ENABLE ||
       // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE
}

control process_dtel_report_encap {
// run only for mirrored packets
// must happen after process_tunnel_encap_outer
#if defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)

#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
        apply(mirror_on_drop_encap){
            nop{
                // defined in dtel_int.p4 and dtel_postcard.p4
                process_dtel_report_encap_();
            }
        }
#else
        apply(mirror_on_drop_encap);
#endif // int_enable || postcard_enable

#elif defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
    // defined in dtel_int.p4 and dtel_postcard.p4
    process_dtel_report_encap_();
#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE

#if !defined(Q0_PROFILE) && !defined(M0_PROFILE)
    process_dtel_report_header_update();
#endif
}

control process_dtel_report_header_update {
#ifdef DTEL_REPORT_ENABLE
    if (valid(dtel_report_header)
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        and dtel_md.drop_flow_suppress == 0
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        ){
        apply(dtel_report_header_update);
    }
#endif
}

control process_dtel_record_egress_port {
#if defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE) ||\
    defined(INT_EP_ENABLE) || \
    defined(POSTCARD_ENABLE)
    apply(dtel_record_egress_port);
#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE ||\
       // INT_EP_ENABLE || POSTCARD_ENABLE
}

/*******************************************************************************
 Common logic for dtel_report_header
 ******************************************************************************/

#ifdef DTEL_REPORT_ENABLE
register dtel_report_header_seqnum {
    width : 32;
    instance_count : 1024; // # mirror sessions
}

blackbox stateful_alu dtel_report_header_seqnum_alu{
    reg: dtel_report_header_seqnum;
    update_lo_1_value: register_lo + 1;
    output_value: register_lo;
    output_dst: dtel_report_header.sequence_number;
}

action update_report_header(){
    dtel_report_header_seqnum_alu.execute_stateful_alu(i2e_metadata.mirror_session_id);
}

table dtel_report_header_update {
    actions {
        update_report_header;
    }
    default_action : update_report_header;
}
#endif // DTEL_REPORT_ENABLE

/*******************************************************************************
 Record egress port
 ******************************************************************************/

#if defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE) || \
    defined(INT_EP_ENABLE) || \
    defined(POSTCARD_ENABLE)

action record_eg_port_from_ig() {
    modify_field(egress_metadata.egress_port,
                 ig_intr_md_for_tm.ucast_egress_port);
}

action record_eg_port_from_eg() {
    modify_field(egress_metadata.egress_port, eg_intr_md.egress_port);
}

action record_eg_port_invalid() {
    modify_field(egress_metadata.egress_port, INVALID_PORT_ID);
}

// deflection, rid  -> action
// 0,          *    -> record_eg_port_from_eg
// 1,          0    -> record_eg_port_from_ig
// 1,          *    -> record_eg_port_invalid
#if !defined(Q0_PROFILE)
@pragma stage 0
#endif
table dtel_record_egress_port {
    reads {
        eg_intr_md.deflection_flag  : exact;
        eg_intr_md.egress_rid       : ternary;
    }
    actions {
        record_eg_port_from_eg;
        record_eg_port_from_ig;
        record_eg_port_invalid;
    }
    size: 3;
}

#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE ||\
       // INT_EP_ENABLE || POSTCARD_ENABLE

/*******************************************************************************
 Switch h/w port to front panel port conversion
 ******************************************************************************/

action ig_port_convert(port) {
// assume DTel mirror packet will not be copied to CPU by egress_system_acl
    modify_field(ingress_metadata.ingress_port, port);
}


// dtel_ig_port_convert runs for mirror copy,
// others run for not a mirror copy
@pragma ignore_table_dependency int_transit_qalert
@pragma ignore_table_dependency dtel_postcard_e2e
@pragma ignore_table_dependency int_sink_local_report
#if !defined(L3_HEAVY_INT_LEAF_PROFILE)
@pragma ternary 1
#endif
#if defined(GENERIC_INT_LEAF_PROFILE) || defined(GENERIC_INT_SPINE_PROFILE) \
    ||defined(MSDC_LEAF_DTEL_INT_PROFILE)
@pragma force_match_dependency egress 9 // reduce power consumption
#endif
table dtel_ig_port_convert {
    reads {
        ingress_metadata.ingress_port : exact;
    }
    actions {
        ig_port_convert;
        nop;
    }
    size: PORT_TABLE_SIZE;
}

action eg_port_convert(port) {
    modify_field(egress_metadata.egress_port, port);
}

// dtel_eg_port_convert runs for mirror copy,
// others run for not a mirror copy
@pragma ignore_table_dependency int_transit_qalert
@pragma ignore_table_dependency dtel_postcard_e2e
@pragma ignore_table_dependency int_sink_local_report
#if !defined(L3_HEAVY_INT_LEAF_PROFILE) && !defined(Q0_PROFILE)
@pragma ternary 1
#endif
#if defined(GENERIC_INT_LEAF_PROFILE) || defined(MSDC_LEAF_DTEL_INT_PROFILE)
@pragma force_match_dependency egress 9 // reduce power consumption
#endif
table dtel_eg_port_convert {
    reads {
        egress_metadata.egress_port   : exact;
    }
    actions {
        eg_port_convert;
        nop;
    }
    size: PORT_TABLE_SIZE;
}

/*******************************************************************************
 Mirror on Drop
 ******************************************************************************/
#ifdef DTEL_DROP_REPORT_ENABLE
action mod_watch_dod(
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    drop_flow_suppress
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    ) {
    modify_field(dtel_md.mod_watchlist_hit, 0x3);
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    modify_field(dtel_md.drop_flow_suppress, drop_flow_suppress);
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    deflect_on_drop(TRUE);
}

action mod_watch_nodod(dod_watchlist
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    , drop_flow_suppress
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    ) {
    modify_field(dtel_md.mod_watchlist_hit, dod_watchlist);
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    modify_field(dtel_md.drop_flow_suppress, drop_flow_suppress);
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

@pragma entries_with_ranges DTEL_DROP_WATCHLIST_RANGE_ENTRIES
table mirror_on_drop_watchlist {
    reads {
        DTEL_FLOW_WATCHLIST
    }
    actions {
        mod_watch_dod;
        mod_watch_nodod;
    }
    size: DTEL_DROP_WATCHLIST_TABLE_SIZE;
}
#endif // DTEL_DROP_REPORT_ENABLE

#if defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)
action mirror_on_drop_outer_update(udp_port, flags, dscp) {
    modify_field(dtel_report_header.merged_fields, flags);
    modify_field(udp.dstPort, udp_port);
    add_to_field(udp.length_, 12); // mirror_on_drop header size is 12B
    add_to_field(ipv4.totalLen, 12); // mirror_on_drop header size is 12B
    modify_field(ipv4.diffserv, dscp, 0xfc);
}

action mirror_on_drop_insert_common(switch_id) {
    add_header(mirror_on_drop_header);
    modify_field(mirror_on_drop_header.switch_id, switch_id);
    modify_field(mirror_on_drop_header.ingress_port,
                 ingress_metadata.ingress_port);
    modify_field(mirror_on_drop_header.egress_port,
                 egress_metadata.egress_port);
    modify_field(mirror_on_drop_header.queue_id, ig_intr_md_for_tm.qid);
    modify_field(mirror_on_drop_header.drop_reason,
                 ingress_metadata.drop_reason);
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    modify_field(dtel_md.drop_flow_suppress, 0);
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

action mirror_on_drop_insert(switch_id, udp_port, flags, dscp) {
    mirror_on_drop_insert_common(switch_id);
    mirror_on_drop_outer_update(udp_port, flags, dscp);
}

#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
action mirror_on_drop_suppress() {
    modify_field(dtel_md.drop_flow_suppress, 1);
}
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE

// nop highest priority
// for all cases priority is not important except DOD that has higher priority
// and mirror_on_drop_suppress that has next higher priority below DOD
// dod can happen because of mod or queue_dod or both
// control plane will not add cases that have "mod" in their dscp if mod feature is disabled
// control plane will not add cases with congested_q=1 if queue_report feature is disabled
@pragma ignore_table_dependency int_outer_encap
table mirror_on_drop_encap {
#ifdef INT_EP_ENABLE
// src, sink, qalert, drop_   mod, drop_  bfilter:
//                    reason,      suprs,
// x,   x,    x,      0,      xx,  x,     xx  : nop (high priority)
// x,   x,    0,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 1,   x,    0,      x,      x1,  x,     xx  : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,   1,    0,      x,      x1,  x,     xx  : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,   0,    1,      DOD,    0x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,   x,    1,      DOD,    0x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,   1,    1,      DOD,    0x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,   0,    1,      DOD,    1x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,   x,    1,      DOD,    1x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// 0,   1,    1,      DOD,    1x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// x,   x,    1,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 0,   0,    1,      x,      x1,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert+mod
// 1,   x,    1,      x,      x1,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,   1,    1,      x,      x1,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,   0,    0,      x,      x1,  x,     xx  : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason   : ternary;
        int_metadata.source            : ternary;
        int_metadata.sink              : ternary;
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert            : ternary;
#endif
#ifdef DTEL_DROP_REPORT_ENABLE
        dtel_md.mod_watchlist_hit      : ternary;
#endif // DTEL_DROP_REPORT_ENABLE
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        dtel_md.drop_flow_suppress     : ternary;
        dtel_md.bfilter_output         : ternary;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    }
#elif defined(INT_TRANSIT_ENABLE)
// path_     qalert, drop_   mod, drop_  bfilter:
// tracking,         reason,      suprs,
// x,        x,      0,      xx,  x,     xx  : nop (high priorty)
// x,        0,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 1,        0,      x,      x1,  x,     xx  : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,        1,      DOD,    0x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,        1,      DOD,    0x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,        1,      DOD,    1x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,        1,      DOD,    1x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// x,        1,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 0,        1,      x,      x1,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert+mod
// 1,        1,      x,      x1,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,        0,      x,      x1,  x,     xx  : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason    : ternary;
        int_metadata.path_tracking_flow : ternary;
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert        : ternary;
#endif // DTEL_QUEUE_REPORT_ENABLE
#ifdef DTEL_DROP_REPORT_ENABLE
        dtel_md.mod_watchlist_hit  : ternary;
#endif // DTEL_DROP_REPORT_ENABLE
    }
#elif defined(POSTCARD_ENABLE)
// report, qalert, drop_   mod, drop_  bfilter:
//                 reason,      suprs,
// x,      x,      0,      xx,  x,     xx  : nop (high priorty)
// x,      0,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 1,      0,      x,      x1,  x,     xx  : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,      1,      DOD,    0x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,      1,      DOD,    0x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,      1,      DOD,    1x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,      1,      DOD,    1x,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// x,      1,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 0,      1,      x,      x1,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert+mod
// 1,      1,      x,      x1,  x,     xx  : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,      0,      x,      x1,  x,     xx  : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason   : ternary;
        postcard_md.report             : ternary;
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert       : ternary;
#endif // DTEL_QUEUE_REPORT_ENABLE
#ifdef DTEL_DROP_REPORT_ENABLE
        dtel_md.mod_watchlist_hit : ternary;
#endif // DTEL_DROP_REPORT_ENABLE
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        dtel_md.drop_flow_suppress     : ternary;
        dtel_md.bfilter_output         : ternary;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    }
#else
// qalert, drop_   mod, drop_  bfilter:
//         reason,      suprs,
// x,      0,      xx,  x,     xx  : nop (high priorty)
// 1,      DOD,    0x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,      DOD,    1x,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// x,      x,      x1,  1,     01  : mirror_on_drop_suppress
// 1,      x,      x1,  x,     xx  : path_tracking=0,congested_q=1,dscp=qalert+mod
// 0,      x,      x1,  x,     xx  : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason : ternary;
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_alert          : ternary;
#endif // DTEL_QUEUE_REPORT_ENABLE
#ifdef DTEL_DROP_REPORT_ENABLE
        dtel_md.mod_watchlist_hit    : ternary;
#endif // DTEL_DROP_REPORT_ENABLE
    }
#endif
    actions {
        mirror_on_drop_insert;
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        mirror_on_drop_suppress;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        nop; // high priority action if drop reason == 0
    }
    size : MIRROR_ON_DROP_ENCAP_TABLE_SIZE;
}

#endif // DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE

/*******************************************************************************
 DTel flow hash
******************************************************************************/
#ifndef DTEL_COMMON_HASH_ENABLE
field_list dtel_flow_hash_fields_outer {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
#if defined(PARSER_EXTRACT_OUTER_ENABLE)
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
#else
    l3_metadata.lkp_outer_l4_sport;
    l3_metadata.lkp_outer_l4_dport;
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
}

field_list dtel_flow_hash_fields_inner {
    lkp_ipv4_hash1_fields;
#ifdef DTEL_WATCH_INNER_ENABLE
    tunnel_metadata.tunnel_vni;
#endif
}

field_list_calculation dtel_flow_hash_outer_calc {
    input { dtel_flow_hash_fields_outer; }
    algorithm : crc32_msb;
    output_width : DTEL_FLOW_HASH_WIDTH;
}

field_list_calculation dtel_flow_hash_inner_calc {
    input { dtel_flow_hash_fields_inner; }
    algorithm : crc32_lsb;
    output_width : DTEL_FLOW_HASH_WIDTH;
}

action compute_flow_hash_outer() {
    modify_field_with_hash_based_offset(
        dtel_md.flow_hash, 0,
        dtel_flow_hash_outer_calc, DTEL_FLOW_HASH_RANGE);
}

action compute_flow_hash_inner() {
    modify_field_with_hash_based_offset(
        dtel_md.flow_hash, 0,
        dtel_flow_hash_inner_calc, DTEL_FLOW_HASH_RANGE);
}

#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 1
#endif
table dtel_flow_hash_outer {
    actions { compute_flow_hash_outer; }
    default_action : compute_flow_hash_outer;
}

// run before adjust_lkp table as it changes the fields that dtel_flow_hash_inner needs
table dtel_flow_hash_inner {
    actions { compute_flow_hash_inner; }
    default_action : compute_flow_hash_inner;
}

#endif /* !DTEL_COMMON_HASH_ENABLE */

field_list dtel_flow_hash_field {
    dtel_md.flow_hash;
}

field_list dtel_flow_eg_hash_fields {
    dtel_md.flow_hash;
#ifndef MULTICAST_DISABLE
    eg_intr_md.egress_rid;
#endif /* MULTICAST DISABLE */
}

/*******************************************************************************
 DTel mirror session selection
 ******************************************************************************/

field_list dtel_session_selection_hash_fields {
    hash_metadata.hash1;
}

field_list_calculation session_selection_hash {
    input {
        dtel_session_selection_hash_fields;
    }
    algorithm : crc16;
    output_width : 14;
}

action_selector dtel_session_selector {
    selection_key : session_selection_hash;
    selection_mode : fair;
}

action set_mirror_session(mirror_id) {
    modify_field(dtel_md.mirror_session_id, mirror_id);
}

action_profile dtel_selector_action_profile {
    actions {
        nop;
        set_mirror_session;
    }
    size : DTEL_MAX_MIRROR_SESSION_PER_GROUP;
    dynamic_action_selection : dtel_session_selector;
}

#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma stage 6
#endif
table dtel_mirror_session {
    reads { ethernet: valid; }
    action_profile: dtel_selector_action_profile;
    //size : DTEL_MAX_SESSION_GROUP;
    size: 2;
}

/*******************************************************************************
 Latency calculation table and actions
 ******************************************************************************/

#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) || defined(INT_DIGEST_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)

action calculate_latency() {
    subtract(dtel_md.quantized_latency,
             eg_intr_md_from_parser_aux.egress_global_tstamp,
             i2e_metadata.ingress_tstamp);
}

#if !defined(Q0_PROFILE)
@pragma stage 0
#endif
table dtel_calculate_latency {
    actions{
        calculate_latency;
    }
    default_action : calculate_latency;
}

action run_dtel_mask_latency(quantization_mask){
    bit_and(dtel_md.quantized_latency,
            dtel_md.quantized_latency, quantization_mask);
}

#ifndef DTEL_QUEUE_REPORT_ENABLE

// we don't have dtel_queue_alert to piggy-back
@pragma stage 1
table dtel_mask_latency {
    actions {
        run_dtel_mask_latency;
    }
    default_action : run_dtel_mask_latency;
}
#endif // DTEL_QUEUE_REPORT_ENABLE
#endif // DTEL_FLOW_STATE_TRACK_ENABLE || INT_DIGEST_DISABLE || \
          DTEL_QUEUE_REPORT_ENABLE

/*******************************************************************************
 Queue latency and depth threshold detection
 ******************************************************************************/

#ifdef DTEL_QUEUE_REPORT_ENABLE

action run_dtel_queue_alert(index, quantization_mask) {
    dtel_queue_alert_alu.execute_stateful_alu(index);
    modify_field(dtel_md.queue_alert_index, index);
    run_dtel_mask_latency(quantization_mask);
}

@pragma stage 1
table dtel_queue_alert {
    reads {
        eg_intr_md.egress_port : exact;
        ig_intr_md_for_tm.qid  : exact;
    }
    actions {
        run_dtel_queue_alert;
        run_dtel_mask_latency;
    }
    size: DTEL_QUEUE_TABLE_SIZE;
}

#if defined(M0_PROFILE)
#define DTEL_QUEUE_REPORT_STAGE 5
#else
#define DTEL_QUEUE_REPORT_STAGE 2
#endif

register dtel_queue_alert_threshold {
    width : 64;
    instance_count : DTEL_QUEUE_TABLE_SIZE;
}

blackbox stateful_alu dtel_queue_alert_alu{
    reg: dtel_queue_alert_threshold;
    condition_lo:  eg_intr_md.deq_qdepth >= register_lo;
    condition_hi:  dtel_md.quantized_latency >= register_hi;
    output_predicate: condition_lo or condition_hi;
    output_value: combined_predicate;
    output_dst: dtel_md.queue_alert;
}

action run_dtel_queue_change() {
    dtel_queue_change_alu.execute_stateful_alu(
        dtel_md.queue_alert_index);
}

// keeping it in the same state as quota tables saves hash bits
@pragma stage DTEL_QUEUE_REPORT_STAGE
table dtel_queue_change {
    actions {
        run_dtel_queue_change;
    }
    default_action : run_dtel_queue_change;
}

register dtel_queue_change_reg {
    width : 32;
    instance_count : DTEL_QUEUE_TABLE_SIZE;
}

blackbox stateful_alu dtel_queue_change_alu {
    reg: dtel_queue_change_reg;
    condition_lo:  dtel_md.quantized_latency != register_lo;
    update_lo_1_value: dtel_md.quantized_latency;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: dtel_md.queue_change;
}

action run_dtel_queue_report_quota() {
    dtel_queue_report_quota_alu.execute_stateful_alu(
        dtel_md.queue_alert_index);
}

// keep dtel_queue_report_quota and dtel_queue_report_dod_quota
// in the same stage to use the same register
@pragma stage DTEL_QUEUE_REPORT_STAGE
table dtel_queue_report_quota {
    actions {
        run_dtel_queue_report_quota;
    }
    default_action : run_dtel_queue_report_quota;
}

action dtel_update_dod_quota(index) {
    dtel_queue_report_dod_quota_alu.execute_stateful_alu(index);
}

// keep dtel_queue_report_quota and dtel_queue_report_dod_quota
// in the same stage to use the same register
@pragma stage DTEL_QUEUE_REPORT_STAGE
table dtel_queue_report_dod_quota {
    reads {
        ig_intr_md_for_tm.ucast_egress_port : exact;
        ig_intr_md_for_tm.qid  : exact;
    }
    actions {
        dtel_update_dod_quota;
        nop;
    }
    size: DTEL_QUEUE_TABLE_SIZE;
}

register dtel_queue_report_quota_reg {
    width : 32;
    instance_count : DTEL_QUEUE_TABLE_SIZE;
}

/* Counter is in register_lo and threshold is in register_hi
 * Upon reset, it copies threshold to low
 * Decrements on each report. If zero stops and 0s the dtel_md.queue_report_quota flag
 * Incrementing the counter from 0 to threshold doesn't work as needs comparing lo and hi
 * in a condition (only one operand from register is possible)
 * Quota value and threshold cannot be 0 even if the index is not used thus set it to nonzero
 * at default and when an index is released
 */
blackbox stateful_alu dtel_queue_report_quota_alu{
    reg: dtel_queue_report_quota_reg;
    condition_lo:  register_lo != 0;
    condition_hi:  dtel_md.queue_alert == 1;
    update_lo_2_predicate: condition_hi and condition_lo;
    update_lo_2_value: register_lo - 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: register_hi;

    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: dtel_md.queue_report_quota;
}

// reset doesn't happen at dod packets
// if register_lo==0, condition_lo=false, so it resets queue_dod_enable
blackbox stateful_alu dtel_queue_report_dod_quota_alu{
    reg: dtel_queue_report_quota_reg;
    condition_lo:  register_lo != 0;
    update_lo_2_predicate: condition_lo;
    update_lo_2_value: register_lo - 1;

    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: dtel_md.queue_dod_enable;
}

action dtel_update_queue_alert(){
    bit_not(dtel_md.queue_alert, dtel_md.queue_alert);
}
action dtel_set_queue_alert(){
    modify_field(dtel_md.queue_alert, 1);
}
action dtel_unset_queue_alert(){
    modify_field(dtel_md.queue_alert, 0);
}

// if qalert == 1 and quota finished and no change, set qalert = 0 to disable queue report
// if qalert == 0 and quota finished, set qalert = 1 to indicate it just went below threshold
// so flipping qalert (qalert=!qalert) in these cases is enough
// (note if qalert == 0 anyway qchange = 0)
// This is added as a matching table vs. an if on this table and negation
// in order to allow the control plane to disable the use of change or quota at runtime.

#if (defined(INT_EP_ENABLE) || defined(POSTCARD_ENABLE))
//#if (defined(INT_EP_ENABLE) || defined(POSTCARD_ENABLE)) && !defined(ENT_FIN_POSTCARD_PROFILE)
// This table usually sits with eg bloom filter, it is better to be ternary to save hash bits
@pragma ternary 1
#endif // INT_EP || POSTCARD
table dtel_queue_alert_update {
// qalert, quota, qchange: new qalert
// 0,      0,     0        1  to show when it went below threshold
// 1,      0,     0        0  to prevent sending packets
    reads {
        dtel_md.queue_alert        : exact;
        dtel_md.queue_report_quota : exact;
        dtel_md.queue_change       : exact;
    }
    actions{
        //dtel_update_queue_alert;
        dtel_unset_queue_alert;
        dtel_set_queue_alert;
        nop;
    }
    size:8;
}

action queue_dod_enb() {
    modify_field(dtel_md.queue_dod_enable, TRUE);
    deflect_on_drop(TRUE);
}

#if defined(Q0_PROFILE) || defined(M0_PROFILE)
@pragma ignore_table_dependency copp_drop
@pragma ignore_table_dependency copp_drop_2
#endif
table deflect_on_drop_queue_config {
    reads {
#ifdef ALT_DOD_CONTROL
        ig_intr_md_for_tm.mcast_grp_a       : exact;
        ig_intr_md_for_tm.mcast_grp_b       : exact;
        ig_intr_md_for_tm.copy_to_cpu       : exact;
        ig_intr_md_for_tm.ucast_egress_port : ternary;
        ig_intr_md_for_tm.qid               : ternary;
#else
        ig_intr_md_for_tm.ucast_egress_port : exact;
        ig_intr_md_for_tm.qid               : exact;
#endif /* ALT_DOD_CONTROL */
    }
    actions {
        queue_dod_enb;
#ifdef ALT_DOD_CONTROL
        invalidate_dod;
#endif /* ALT_DOD_CONTROL */
        nop;
    }
    size: DTEL_QUEUE_TABLE_SIZE;
}

#endif // DTEL_QUEUE_REPORT_ENABLE

/*******************************************************************************
 Stateful flow state change detection
 ******************************************************************************/

#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
// 4 Hash computation for ingress flow state change detection.
field_list_calculation dtel_hash_1 {
    input { dtel_flow_hash_field; }
    algorithm : crc_16;
    output_width : DTEL_HASH_WIDTH;
}

field_list_calculation dtel_hash_2 {
    input { dtel_flow_hash_field; }
    algorithm : crc_16_dect;
    output_width : DTEL_HASH_WIDTH;
}

field_list_calculation dtel_hash_3 {
    input { dtel_flow_hash_field; }
    algorithm : crc_16_dnp;
    output_width : DTEL_HASH_WIDTH;
}

field_list_calculation dtel_hash_4 {
    input { dtel_flow_hash_field; }
// random algorihtm selected at compile time per p4 program
    algorithm : crc_16_genibus;
    output_width : DTEL_HASH_WIDTH;
}
#endif // DTEL_FLOW_STATE_TRACK_ENABLE

#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) || \
    defined(DTEL_DROP_FLOW_STATE_TRACK_ENABLE)
// 4 Hash computation for egress flow state change detection.
field_list_calculation dtel_eg_hash_1 {
    input { dtel_flow_eg_hash_fields; }
    algorithm : crc_16;
    output_width : DTEL_HASH_WIDTH;
}

field_list_calculation dtel_eg_hash_2 {
    input { dtel_flow_eg_hash_fields; }
    algorithm : crc_16_dect;
    output_width : DTEL_HASH_WIDTH;
}

field_list_calculation dtel_eg_hash_3 {
    input { dtel_flow_eg_hash_fields; }
    algorithm : crc_16_dnp;
    output_width : DTEL_HASH_WIDTH;
}

field_list_calculation dtel_eg_hash_4 {
    input { dtel_flow_eg_hash_fields; }
// random algorihtm selected at compile time per p4 program
    algorithm : crc_16_genibus;
    output_width : DTEL_HASH_WIDTH;
}

// Bloom Filters for detecting local flow state changes.

// A bit vector representing the filter. Replicated per hash function.
register dtel_eg_bfilter_reg_1{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_eg_bfilter_1;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}
register dtel_eg_bfilter_reg_2{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_eg_bfilter_2;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}
register dtel_eg_bfilter_reg_3{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_eg_bfilter_3;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}
register dtel_eg_bfilter_reg_4{
    width : DTEL_DIGEST_WIDTH;
    static : dtel_eg_bfilter_4;
    instance_count : DTEL_BLOOM_FILTER_SIZE;
}

blackbox stateful_alu dtel_eg_bfilter_alu_1{
    reg: dtel_eg_bfilter_reg_1;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == dtel_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: dtel_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: dtel_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

blackbox stateful_alu dtel_eg_bfilter_alu_2{
    reg: dtel_eg_bfilter_reg_2;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == dtel_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: dtel_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: dtel_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

blackbox stateful_alu dtel_eg_bfilter_alu_3{
    reg: dtel_eg_bfilter_reg_3;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == dtel_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: dtel_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: dtel_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

blackbox stateful_alu dtel_eg_bfilter_alu_4{
    reg: dtel_eg_bfilter_reg_4;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == dtel_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: dtel_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: dtel_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

action run_dtel_eg_bfilter_1() {
    dtel_eg_bfilter_alu_1.execute_stateful_alu_from_hash(dtel_eg_hash_1);
}
action run_dtel_eg_bfilter_2() {
    dtel_eg_bfilter_alu_2.execute_stateful_alu_from_hash(dtel_eg_hash_2);
}
action run_dtel_eg_bfilter_3() {
    dtel_eg_bfilter_alu_3.execute_stateful_alu_from_hash(dtel_eg_hash_3);
}
action run_dtel_eg_bfilter_4() {
    dtel_eg_bfilter_alu_4.execute_stateful_alu_from_hash(dtel_eg_hash_4);
}

/* Four separate tables to run the bloom filter. */
/* pragmas to keep tables in the same stage */
#if defined(Q0_PROFILE)
#define DTEL_EG_BF_STAGE 5
#elif defined(M0_PROFILE)
#define DTEL_EG_BF_STAGE 7
#else
#define DTEL_EG_BF_STAGE 4
#endif
#ifdef DTEL_EG_BF_STAGE
@pragma stage DTEL_EG_BF_STAGE
#endif
table dtel_eg_bfilter_1 {
    actions { run_dtel_eg_bfilter_1; }
    default_action : run_dtel_eg_bfilter_1;
}
#ifdef DTEL_EG_BF_STAGE
@pragma stage DTEL_EG_BF_STAGE
#endif
table dtel_eg_bfilter_2 {
    actions { run_dtel_eg_bfilter_2; }
    default_action : run_dtel_eg_bfilter_2;
}
#ifdef DTEL_EG_BF_STAGE
@pragma stage DTEL_EG_BF_STAGE
#endif
table dtel_eg_bfilter_3 {
    actions { run_dtel_eg_bfilter_3; }
    default_action : run_dtel_eg_bfilter_3;
}
#ifdef DTEL_EG_BF_STAGE
@pragma stage DTEL_EG_BF_STAGE
#endif
table dtel_eg_bfilter_4 {
    actions { run_dtel_eg_bfilter_4; }
    default_action : run_dtel_eg_bfilter_4;
}

#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
field_list dtel_local_digest_fields {
// includes flow hash to avoid canceling reports of microbursts
// for two different flows and reduces the probabilty of missing changes
    dtel_md.flow_hash;
#ifndef MULTICAST_DISABLE
    eg_intr_md.egress_rid;
#endif /* MULTICAST DISABLE */
    dtel_md.quantized_latency;
    ingress_metadata.ingress_port;
    eg_intr_md.egress_port;
}

field_list_calculation dtel_local_digest_calc {
    input { dtel_local_digest_fields; }
    algorithm : crc_16_teledisk;
    output_width : DTEL_DIGEST_WIDTH;
}

action make_local_digest() {
    modify_field_with_hash_based_offset(
        dtel_md.local_digest, 0,
        dtel_local_digest_calc, DTEL_DIGEST_RANGE);
}
#endif // DTEL_FLOW_STATE_TRACK_ENABLE

#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
field_list dtel_drop_digest_fields {
// includes flow hash to avoid canceling reports for two different flows
// and reduces the probability of missing changes
    dtel_md.flow_hash;
    ingress_metadata.drop_reason;
    ingress_metadata.ingress_port;
}

field_list_calculation dtel_drop_digest_calc {
    input { dtel_drop_digest_fields; }
    algorithm : crc_16_teledisk;
    output_width : DTEL_DIGEST_WIDTH;
}

action make_drop_digest() {
    modify_field_with_hash_based_offset(
        dtel_md.local_digest, 0,
        dtel_drop_digest_calc, DTEL_DIGEST_RANGE);
}
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE

#ifdef GENERIC_INT_LEAF_PROFILE
@pragma stage 3
#endif
table dtel_make_local_digest {
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
// clone_src
// 0          : make_local_digest
// 1          : make_drop_digest
// 3          : make_drop_digest
    reads {
        eg_intr_md_from_parser_aux.clone_src  : exact;
    }
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    actions {
#ifdef DTEL_FLOW_STATE_TRACK_ENABLE
        make_local_digest;
#endif // DTEL_FLOW_STATE_TRACK_ENABLE
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        make_drop_digest;
        nop;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    }
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    default_action : nop;
    size : 4;
#elif defined(DTEL_FLOW_STATE_TRACK_ENABLE)
    default_action : make_local_digest;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
action dtel_rewrite_rid(rid) {
    modify_field(eg_intr_md.egress_rid, rid);
}

action dtel_clear_drop_flow_suppress() {
    modify_field(dtel_md.drop_flow_suppress, 0);
}

/* For mirrored packets, assuming original packet was unicast:
 *   - Set egress_rid to 0 to hit same eg_bfilter entry as not mirrored packets
 *     - Saves eg_bfilter entries
 *     - Reports when drops cease to occur
 *     - May generate excessive reports if toggling between dropped/not dropped
 *     Do NOT set egress_rid to 0 if egress mirror but not a TM drop, since
 *     each packet toggles the bloom filter between the two egress passes.
 *   - Set egress_rid to a non-zero value to hit a different entry
 *     - Uses up to two eg_bfilter entries per flow
 *     - Dropped and not dropped reports are suppressed independently
 *
 * When drop_reason == TM and mod_watchlist_hit == 0x0x
 * (drop reports do not include tail drops),
 * clear drop_flow_suppress in order to save bloom filter entries.
 *
 * clone_src, drop_reason, mod_watchlist_hit
 * 1          x            xx                  dtel_rewrite_rid(0)
 * 3          DOD          0x                  dtel_clear_drop_flow_suppress
 * 3          x            xx (lower priority) dtel_rewrite_rid(!0)
 */
table dtel_drop_suppress_prepare {
    reads {
        eg_intr_md_from_parser_aux.clone_src  : exact;
        ingress_metadata.drop_reason          : ternary;
        dtel_md.mod_watchlist_hit             : ternary;
    }
    actions {
        dtel_rewrite_rid;
        dtel_clear_drop_flow_suppress;
        nop;
    }
    default_action : nop;
    size : 5;
}
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE

control process_dtel_detect_local_change {
    // Use bloom filter to detect change in quantized local latency
    // This should be executed before tunnel_decap
    apply(dtel_eg_bfilter_1);
#ifndef DTEL_BF_1_WAY_HASH_ENABLE
    apply(dtel_eg_bfilter_2);
#ifndef DTEL_BF_2_WAY_HASH_ENABLE
    apply(dtel_eg_bfilter_3);
#ifndef DTEL_BF_3_WAY_HASH_ENABLE
    apply(dtel_eg_bfilter_4);
#endif // !DTEL_BF_3_WAY_HASH_ENABLE
#endif // !DTEL_BF_2_WAY_HASH_ENABLE
#endif // !DTEL_BF_1_WAY_HASH_ENABLE
}
#endif // DTEL_FLOW_STATE_TRACK_ENABLE || DTEL_DROP_FLOW_STATE_TRACK_ENABLE
