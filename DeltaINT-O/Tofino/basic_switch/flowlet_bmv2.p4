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
 * Flowlet related processing for BMv2
 */

#if !defined(__TARGET_TOFINO__)
header_type flowlet_metadata_t {
    fields {
        id : 16;                            /* flowlet id */
        enable : 32;                        /* flowlet inactivity timeout */
        timestamp : 32;                     /* flowlet last time stamp */
        map_index : FLOWLET_MAP_WIDTH;      /* flowlet map index */
        inter_packet_gap : 32;              /* inter-packet gap */
    }
}

metadata flowlet_metadata_t flowlet_metadata;

register flowlet_id {
    width : 16;
    instance_count : FLOWLET_MAP_SIZE;
}

register flowlet_lastseen {
    width : 32;
    instance_count : FLOWLET_MAP_SIZE;
}

action update_flowlet_id() {
    add_to_field(flowlet_metadata.id, 1);
    register_write(flowlet_id, flowlet_metadata.map_index,
                   flowlet_metadata.id);
}

table new_flowlet {
    actions {
        update_flowlet_id;
    }
    default_action : update_flowlet_id;
    size : 1;
}

action flowlet_lookup() {
    // this action implementation assumes sequential execution semantics.
    modify_field_with_hash_based_offset(flowlet_metadata.map_index, 0,
                                        flowlet_hash, FLOWLET_MAP_SIZE);
    modify_field(flowlet_metadata.inter_packet_gap,
                 intrinsic_metadata.ingress_global_timestamp);
    register_read(flowlet_metadata.id, flowlet_id,
                  flowlet_metadata.map_index);
    register_read(flowlet_metadata.timestamp, flowlet_lastseen,
                  flowlet_metadata.map_index);
    subtract_from_field(flowlet_metadata.inter_packet_gap,
                        flowlet_metadata.timestamp);
    register_write(flowlet_lastseen, flowlet_metadata.map_index,
                   intrinsic_metadata.ingress_global_timestamp);
}
#endif /* __TARGET_TOFINO__ */
