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
 * Security related processing - Storm control, IPSG, etc.
 */

/*
 * security metadata
 */
#ifndef IPSG_DISABLE
header_type security_metadata_t {
    fields {
        ipsg_enabled : 1;                      /* is ip source guard feature enabled */
        ipsg_check_fail : 1;                   /* ipsg check failed */
    }
}

metadata security_metadata_t security_metadata;
#endif /* IPSG_DISABLE */

#ifndef STORM_CONTROL_DISABLE
/*****************************************************************************/
/* Storm control                                                             */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter storm_control_stats {
    type : packets;
    direct : storm_control_stats;
}

table storm_control_stats {
    reads {
        meter_metadata.storm_control_color: exact;
        l2_metadata.lkp_pkt_type : ternary;
        ig_intr_md.ingress_port: exact;
        l2_metadata.l2_dst_miss : ternary;
    }
    actions {
        nop;
    }
    size: STORM_CONTROL_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

meter storm_control_meter {
    type : bytes;
    static : storm_control;
    result : meter_metadata.storm_control_color;
    instance_count : STORM_CONTROL_METER_TABLE_SIZE;
}

action set_storm_control_meter(meter_idx) {
    execute_meter(storm_control_meter, meter_idx,
                  meter_metadata.storm_control_color);
}

table storm_control {
    reads {
        ig_intr_md.ingress_port : exact;
        l2_metadata.lkp_pkt_type : ternary;
        l2_metadata.l2_dst_miss : ternary;
    }
    actions {
        nop;
        set_storm_control_meter;
    }
    size : STORM_CONTROL_TABLE_SIZE;
}
#endif /* STORM_CONTROL_DISABLE */

control process_storm_control {
#ifndef STORM_CONTROL_DISABLE
    if (ingress_metadata.port_type == PORT_TYPE_NORMAL) {
        apply(storm_control);
    }
#endif /* STORM_CONTROL_DISABLE */
}

control process_storm_control_stats {
#ifndef STORM_CONTROL_DISABLE
#ifndef STATS_DISABLE
    apply(storm_control_stats);
#endif /* STATS_DISABLE */
#endif /* STORM_CONTROL_DISABLE */
}


#ifndef IPSG_DISABLE
/*****************************************************************************/
/* IP Source Guard                                                           */
/*****************************************************************************/
action ipsg_miss() {
    modify_field(security_metadata.ipsg_check_fail, TRUE);
}

table ipsg_permit_special {
    reads {
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_dport : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
    }
    actions {
        ipsg_miss;
    }
    size : IPSG_PERMIT_SPECIAL_TABLE_SIZE;
}

table ipsg {
    reads {
        ingress_metadata.ifindex : exact;
        ingress_metadata.bd : exact;
        l2_metadata.lkp_mac_sa : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
    }
    actions {
        on_miss;
    }
    size : IPSG_TABLE_SIZE;
}
#endif /* IPSG_DISABLE */

control process_ip_sourceguard {
#ifndef IPSG_DISABLE
    /* l2 security features */
    if ((ingress_metadata.port_type == PORT_TYPE_NORMAL) and
        (security_metadata.ipsg_enabled == TRUE)) {
        apply(ipsg) {
            on_miss {
                apply(ipsg_permit_special);
            }
        }
    }
#endif /* IPSG_DISABLE */
}
