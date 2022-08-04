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
 * Fast failover processing
 */

#ifdef FAST_FAILOVER_ENABLE
header_type failover_metadata_t {
    fields {
        index : 17;
        fallback_check : 1;
    }
}
metadata failover_metadata_t failover_metadata;

action drop_failover_pkt() {
    drop();
}

action recirc_failover_pkt(recirc_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, recirc_port);
}

/*****************************************************************************/
/* LAG failover                                                              */
/*****************************************************************************/
register lag_failover_reg {
    width : 1;
    instance_count : LAG_FAILOVER_REG_INSTANCE_COUNT;
}

blackbox stateful_alu lag_failover_alu {
    reg : lag_failover_reg;
    selector_binding : lag_group;
    update_lo_1_value : clr_bit;
}

/* Recirc the port down packet to be porcessed by other pipelines as well. */
/* Last pipeline drops the port down message. */
table lag_failover_recirc {
    reads {
        pktgen_port_down.pipe_id : exact;
    }
    actions {
        recirc_failover_pkt;
        drop_failover_pkt;
    }
    size : 2;
}

action deactivate_lag_member() {
    lag_failover_alu.execute_stateful_alu(failover_metadata.index);
}

/* Must be in the same stage as lag_group */
table lag_failover {
    actions {
        deactivate_lag_member;
    }
    default_action : deactivate_lag_member;
    size : 1;
}

action set_lag_failover_index(index) {
    modify_field(failover_metadata.index, index);
    modify_field(ingress_metadata.bypass_lookups, BYPASS_ALL);
}

table lag_failover_lookup {
    reads {
        pktgen_port_down.port_num : exact;
        pktgen_port_down.packet_id : exact;
    }
    actions {
        set_lag_failover_index;
        drop_failover_pkt;  /* default action */
    }
    size : LAG_FAILOVER_TABLE_SIZE;
}

/*****************************************************************************/
/* ECMP failover                                                             */
/*****************************************************************************/
register ecmp_failover_reg {
    width : 1;
    instance_count : ECMP_FAILOVER_REG_INSTANCE_COUNT;
}

action drop_nhop_down_pkt() {
    drop();
}

action prepare_for_recirc() {
    add_header(pktgen_recirc);
    add_header(pktgen_ext_header);
    modify_field(pktgen_recirc._pad0, 0xf);
    modify_field(pktgen_recirc.app_id, P4_PKTGEN_APP_ECMP_FAILOVER);
    modify_field(pktgen_recirc.pipe_id, 0);
    modify_field(pktgen_recirc.key, l3_metadata.nexthop_index);
    modify_field(pktgen_recirc.packet_id, 0xffff);
    modify_field(pktgen_ext_header.pad, 0);
    modify_field(pktgen_ext_header.etherType, ETHERTYPE_BF_PKTGEN);
}

table prepare_for_recirc {
    actions {
        prepare_for_recirc;
    }
    default_action : prepare_for_recirc;
    size : 1;
}

/* Recirc the nhop down packet to be porcessed by other pipelines as well. */
/* Last pipeline drops the nhop down message. */
table ecmp_failover_recirc {
    reads {
        ig_intr_md.ingress_port mask 0x180: exact;
    }
    actions {
        recirc_failover_pkt;
        drop_failover_pkt;
    }
    size : 2;
}

blackbox stateful_alu ecmp_failover_alu {
    reg : ecmp_failover_reg;
    selector_binding : ecmp_group;
    update_lo_1_value : clr_bit;
}

action deactivate_ecmp_member() {
    ecmp_failover_alu.execute_stateful_alu(failover_metadata.index);
}

// Must be in the same stage as lag_group
table ecmp_failover {
    actions {
        deactivate_ecmp_member;
    }
    default_action : deactivate_ecmp_member;
    size : 1;
}

action set_ecmp_failover_index(index) {
    modify_field(failover_metadata.index, index);
    modify_field(ingress_metadata.bypass_lookups, BYPASS_ALL);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_ECMP);
}

table ecmp_failover_lookup {
    reads {
        pktgen_recirc.packet_id : exact;
        pktgen_recirc.key mask 0xff : exact;
    }
    actions {
        set_ecmp_failover_index;
        drop_failover_pkt;  /* default action */
    }
    size : ECMP_FAILOVER_TABLE_SIZE;
}
#endif /* FAST_FAILOVER_ENABLE */

control process_pktgen_port_down {
#ifdef FAST_FAILOVER_ENABLE
    apply(lag_failover_lookup);
#endif /* FAST_FAILOVER_ENABLE */
}

control process_pktgen_nhop_down {
#ifdef FAST_FAILOVER_ENABLE
    apply(ecmp_failover_lookup);
#endif /* FAST_FAILOVER_ENABLE */
}

control process_lag_fallback {
#ifdef FAST_FAILOVER_ENABLE
    if (failover_metadata.fallback_check == 1) {
       apply(prepare_for_recirc);
    }
#endif
}
