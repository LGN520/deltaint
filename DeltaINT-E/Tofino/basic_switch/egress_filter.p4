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
 * Egress filtering logic, used only in open source version.
 */
/*****************************************************************************/
/* Egress filtering logic                                                    */
/*****************************************************************************/
#ifdef EGRESS_FILTER
header_type egress_filter_metadata_t {
    fields {
        ifindex_check : IFINDEX_BIT_WIDTH;     /* src port filter */
        bd : BD_BIT_WIDTH;                     /* bd for src port filter */
        inner_bd : BD_BIT_WIDTH;               /* split horizon filter */
    }
}
metadata egress_filter_metadata_t egress_filter_metadata;

action egress_filter_check() {
    bit_xor(egress_filter_metadata.ifindex_check, ingress_metadata.ifindex,
            ingress_metadata.egress_ifindex);
    bit_xor(egress_filter_metadata.bd, ingress_metadata.outer_bd,
            egress_metadata.outer_bd);
    bit_xor(egress_filter_metadata.inner_bd, ingress_metadata.bd,
            egress_metadata.bd);
}

action set_egress_filter_drop() {
    drop();
}

table egress_filter_drop {
    actions {
        set_egress_filter_drop;
    }
    default_action : set_egress_filter_drop;
}

table egress_filter {
    actions {
        egress_filter_check;
    }
    default_action : egress_filter_check;
}
#endif /* EGRESS_FILTER */

control process_egress_filter {
#ifdef EGRESS_FILTER
    apply(egress_filter);
    if (multicast_metadata.inner_replica == TRUE) {
        if (((tunnel_metadata.ingress_tunnel_type == INGRESS_TUNNEL_TYPE_NONE) and
             (tunnel_metadata.egress_tunnel_type == EGRESS_TUNNEL_TYPE_NONE) and
             (egress_filter_metadata.bd == 0) and
             (egress_filter_metadata.ifindex_check == 0)) or
            ((tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) and
             (tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE)) and
             (egress_filter_metadata.inner_bd == 0)) {
            apply(egress_filter_drop);
        }
    }
#endif /* EGRESS_FILTER */
}
