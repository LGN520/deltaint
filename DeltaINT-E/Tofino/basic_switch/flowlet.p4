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
 * Flowlet related processing
 */

#include "flowlet_bmv2.p4"

#if defined(__TARGET_TOFINO__)
/*
 * flowlet metadata
 */

// This is an arbitrary large prime number to make sure enough number of bits
// in flowlet-id will be changed and hence, CRC16 hash value have enough
// entropy to pick all memebers of a ECMP/LAG group.
#define FLOWLET_ID_INCREMENT 997
#define FLOWLET_INACTIVE_TIMEOUT 1

header_type flowlet_metadata_t {
    fields {
        id : 16;                            /* flowlet id */
        enable : 1;
    }
}

metadata flowlet_metadata_t flowlet_metadata;

register flowlet_state {
    width : 64;
    instance_count : FLOWLET_MAP_SIZE;
}

blackbox stateful_alu flowlet_alu {
    reg : flowlet_state;
    initial_register_hi_value : 0;
    initial_register_lo_value : 0;
    //TODO inactivity_tout should be configurable.
    // (global_ts - flowlet_lastseen) > inactivity_tout
    condition_lo : i2e_metadata.ingress_tstamp - register_lo > FLOWLET_INACTIVE_TIMEOUT;
    update_lo_2_value : i2e_metadata.ingress_tstamp;
    update_hi_1_value : register_hi + FLOWLET_ID_INCREMENT;
    update_hi_1_predicate: condition_lo;
    update_hi_2_value : register_hi;
    update_hi_2_predicate: not condition_lo;
    output_value : alu_hi;
    output_dst : flowlet_metadata.id;
}

action flowlet_lookup() {
    flowlet_alu.execute_stateful_alu_from_hash(flowlet_hash);
}
#endif /* __TARGET_TOFINO__ */

field_list flowlet_hash_fields {
    hash_metadata.hash1;
}

field_list_calculation flowlet_hash {
    input {
        flowlet_hash_fields;
    }
    algorithm : identity;
    output_width : FLOWLET_MAP_WIDTH;
}

table flowlet {
    actions {
        flowlet_lookup;
    }
    default_action : flowlet_lookup;
    size : 1;
}

control process_flowlet {
#ifdef FLOWLET_ENABLE
    if (flowlet_metadata.enable != 0) {
        apply(flowlet);

#if !defined(__TARGET_TOFINO__)
        if (flowlet_metadata.inter_packet_gap > flowlet_metadata.enable) {
            apply(new_flowlet);
        }
#endif /* __TARGET_TOFINO__ */
    }
#endif /* FLOWLET_ENABLE */
}
