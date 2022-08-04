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
/*******************************************************************************
 *                      Intrinsic Metadata Definition for Tofino               *
 ******************************************************************************/

header_type ingress_parser_control_signals {
    fields {
        priority : 3;                   // set packet priority
        parser_counter : 8;             // parser counter
   }
}
metadata ingress_parser_control_signals ig_prsr_ctrl;

header_type ingress_intrinsic_metadata_t {
    fields {
        resubmit_flag : 1;              // flag distinguishing original packets
                                        // from resubmitted packets.

        ingress_port : 9;               // ingress physical port id.

        ingress_global_tstamp : 48;     // global timestamp (ns) taken upon
                                        // arrival at ingress.

        lf_field_list : 32;             // hack for learn filter.
    }
}
metadata ingress_intrinsic_metadata_t ig_intr_md;

header_type ingress_intrinsic_metadata_for_tm_t {
    fields {
        ucast_egress_port : 9;          // egress port for unicast packets.

        drop_ctl : 3;                   // drop control

        mcast_grp_a : 16;               // 1st multicast group (i.e., tree) id;
                                        // a tree can have two levels. must be
                                        // presented to TM for multicast.

        mcast_grp_b : 16;               // 2nd multicast group (i.e., tree) id;
                                        // a tree can have two levels.

        level1_mcast_hash : 13;         // source of entropy for multicast
                                        // replication-tree level1 (i.e., L3
                                        // replication). must be presented to TM
                                        // for L3 dynamic member selection
                                        // (e.g., ECMP) for multicast.

        level2_mcast_hash : 13;         // source of entropy for multicast
                                        // replication-tree level2 (i.e., L2
                                        // replication). must be presented to TM
                                        // for L2 dynamic member selection
                                        // (e.g., LAG) for nested multicast.

        level1_exclusion_id : 16;       // exclusion id for multicast
                                        // replication-tree level1. used for
                                        // pruning.

        level2_exclusion_id : 9;        // exclusion id for multicast
                                        // replication-tree level2. used for
                                        // pruning.

        rid : 16;                       // L3 replication id for multicast.
                                        // used for pruning.
        deflect_on_drop : 1;            // flag indicating whether a packet can
                                        // be deflected by TM on congestion drop
        ingress_cos : 3;                // ingress cos (iCoS) for PG mapping,
                                        // ingress admission control, PFC,
                                        // etc.

        qid : 5;                        // egress (logical) queue id into which
                                        // this packet will be deposited.

        packet_color : 2;               // packet color (G,Y,R) that is
                                        // typically derived from meters and
                                        // used for color-based tail dropping.
        disable_ucast_cutthru : 1;      // disable cut-through forwarding for
                                        // unicast.
        enable_mcast_cutthru : 1;       // enable cut-through forwarding for
                                        // multicast.
    }
}

metadata ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm;

header_type egress_intrinsic_metadata_t {
    fields {
        egress_port : 9;               // egress port id.

        enq_qdepth : 19;                // queue depth at the packet enqueue
                                        // time.

        enq_congest_stat : 2;           // queue congestion status at the packet
                                        // enqueue time.

        enq_tstamp : 32;                // time snapshot taken when the packet
                                        // is enqueued (in nsec).

        deq_qdepth : 19;                // queue depth at the packet dequeue
                                        // time.

        deq_congest_stat : 2;           // queue congestion status at the packet
                                        // dequeue time.

        app_pool_congest_stat : 8;      // dequeue-time application-pool
                                        // congestion status. 2bits per
                                        // pool.

        deq_timedelta : 32;             // time delta between the packet's
                                        // enqueue and dequeue time.

        egress_rid : 16;                // L3 replication id for multicast
                                        // packets.

        egress_rid_first : 1;           // flag indicating the first replica for
                                        // the given multicast group.

        egress_qid : 5;                 // egress (physical) queue id via which
                                        // this packet was served.

        egress_cos : 3;                 // egress cos (eCoS) value.

        deflection_flag : 1;            // flag indicating whether a packet is
                                        // deflected due to deflect_on_drop.
    }
}

metadata egress_intrinsic_metadata_t eg_intr_md;

/* primitive/library function extensions */

action deflect_on_drop(enable_dod) {
    modify_field(ig_intr_md_for_tm.deflect_on_drop, enable_dod);
}

#define _ingress_global_tstamp_     intrinsic_metadata.ingress_global_timestamp

header_type egress_intrinsic_metadata_from_parser_aux_t {
    fields {
        clone_src : 8;
        egress_global_tstamp: 48;
    }
}
metadata egress_intrinsic_metadata_from_parser_aux_t eg_intr_md_from_parser_aux;

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

// XXX check other types RECIRC etc and exclude those
#define pkt_is_mirrored \
    ((standard_metadata.instance_type != PKT_INSTANCE_TYPE_NORMAL) and \
     (standard_metadata.instance_type != PKT_INSTANCE_TYPE_REPLICATION))
#define pkt_is_not_mirrored \
    ((standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) or \
     (standard_metadata.instance_type == PKT_INSTANCE_TYPE_REPLICATION))
#define pkt_is_i2e_mirrored \
    (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE)
#define pkt_is_e2e_mirrored \
    (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE)
