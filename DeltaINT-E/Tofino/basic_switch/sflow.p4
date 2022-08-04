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
 * Sflow processing
 */
#ifdef SFLOW_ENABLE
header_type sflow_metadata_t {
    fields {
        take_sample : 8;
        session_id : 16;
    }
}

metadata sflow_metadata_t sflow_metadata;

counter sflow_ingress_session_pkt_counter {
    type : packets;
    direct : sflow_ingress;
    saturating;
}
#endif

/* ---------------------- sflow ingress processing ------------------------ */
#ifdef SFLOW_ENABLE

action set_sflow_parameters() {
    /* use random number generator to decide to take a sample */
    modify_field_rng_uniform(sflow_metadata.take_sample, 0, 0xFFFF);
}

table sflow_config {
    actions {
        set_sflow_parameters;
    }
    default_action : set_sflow_parameters;
    size : 1;
}

table sflow_ingress {
    /* Table to determine ingress port based enablement */
    /* This is separate from ACLs so that this table can be applied */
    /* independent of ACLs */
    reads {
        ingress_metadata.port_lag_index : ternary;
        sflow_metadata.take_sample : range;
        sflow : valid; /* do not sflow an sflow frame */
    }
    actions {
        nop; /* default action */
        sflow_ing_pkt_to_cpu;
    }
    size : SFLOW_INGRESS_TABLE_SIZE;
}

field_list sflow_cpu_info {
    cpu_info;
    sflow_metadata.session_id;
    i2e_metadata.mirror_session_id;
}

action sflow_ing_pkt_to_cpu(sflow_i2e_mirror_id, session_id) {
    modify_field(sflow_metadata.session_id, session_id);
    modify_field(i2e_metadata.mirror_session_id, sflow_i2e_mirror_id);
    clone_ingress_pkt_to_egress(sflow_i2e_mirror_id, sflow_cpu_info);
}
#endif /*SFLOW_ENABLE */

control process_ingress_sflow {
#ifdef SFLOW_ENABLE
    apply(sflow_ingress);
#endif
}


/* ----- egress processing ----- */
#ifdef SFLOW_ENABLE
action sflow_pkt_to_cpu(reason_code) {
    /* This action is called from the mirror table in the egress pipeline */
    /* Add sflow header to the packet */
    /* sflow header sits between cpu header and the rest of the original packet */
    /* The reasonCode in the cpu header is used to identify the */
    /* presence of the cpu header */
    /* pkt_count(sample_pool) on a given sflow session is read directly by CPU */
    /* using counter read mechanism */
    add_header(fabric_header_sflow);
    modify_field(fabric_header_sflow.sflow_session_id,
                 sflow_metadata.session_id);
    modify_field(fabric_metadata.reason_code, reason_code);
}
#endif
