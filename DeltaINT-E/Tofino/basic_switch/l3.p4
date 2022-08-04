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
 * Layer-3 processing
 */

/*
 * L3 Metadata
 */

header_type l3_metadata_t {
    fields {
#ifdef IP_TYPE_EXTENSION_ENABLE
        lkp_ip_type : 3;
#else
        lkp_ip_type : 2;
#endif
        lkp_ip_version : 4;
        lkp_ip_proto : 8;
        lkp_dscp : 8;
        lkp_ip_ttl : 8;
        lkp_l4_sport : 16;
        lkp_l4_dport : 16;
        lkp_outer_l4_sport : 16;
        lkp_outer_l4_dport : 16;
        lkp_outer_tcp_flags : 8;
        lkp_inner_l4_sport : 16;
        lkp_inner_l4_dport : 16;
        lkp_inner_tcp_flags : 8;
        lkp_tcp_flags : 8;
        lkp_ip_llmc : 1;
        lkp_ip_mc : 1;
        lkp_ip_frag : 2;                       /* Flag indicating IP packet is fragmented.
                                                    00 : Not fragmented.
                                                    10 : Fragmented with non-zero offset.
                                                    11 : Fragmented with fragOffset of zero. */
        vrf : VRF_BIT_WIDTH;                   /* VRF */
        rmac_group : RMAC_GROUP_BIT_WIDTH;     /* Rmac group, for rmac indirection */
        rmac_hit : 1;                          /* dst mac is the router's mac */
#if !defined(URPF_DISABLE)
        urpf_mode : 2;                         /* urpf mode for current lookup */
        urpf_hit : 1;                          /* hit in urpf table */
        urpf_check_fail :1;                    /* urpf check failed */
        urpf_bd_group : BD_BIT_WIDTH;          /* urpf bd group */
#endif /* !URPF_DISABLE */
        fib_hit : 1;                           /* fib hit */
        fib_hit_myip : 1;                      /* fib hit on router ip address */
        fib_nexthop : NEXTHOP_BIT_WIDTH;       /* next hop from fib */
        fib_nexthop_type : 1;                  /* ecmp or nexthop */
        fib_label : 8;                         /* destination fib label */
        fib_partition_index : 12;              /* partition index for atcam */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */
        nexthop_index : NEXTHOP_BIT_WIDTH;     /* nexthop/rewrite index */
        nexthop_dmac : 48;
        ipv6_da_idx12 : 12;
        ipv6_da_var16 : 16;
        ipv6_da_var40 : 40;
        routed : 1;                            /* is packet routed? */
        outer_routed : 1;                      /* is outer packet routed? */
        mtu_index : 8;                         /* index into mtu table */
        l3_copy : 1;                           /* copy packet to CPU */
        l3_mtu_check : 16 (saturating);        /* result of mtu check */

        egress_l4_sport : 16;
        egress_l4_dport : 16;
#ifdef ROCEV2_MIRROR_ENABLE
        rocev2_opcode : 8;
        rocev2_ack_req_rsvd : 8;
        rocev2_dst_qp_plus_rsvd : 32;
        rocev2_aeth_syndrome : 8;
#endif /* ROCEV2_MIRROR_ENABLE */
    }
}

#ifdef TUNNEL_PARSING_DISABLE
@pragma pa_alias ingress l3_metadata.lkp_outer_l4_sport l3_metadata.lkp_l4_sport
@pragma pa_alias ingress l3_metadata.lkp_outer_l4_dport l3_metadata.lkp_l4_dport
@pragma pa_alias ingress l3_metadata.lkp_outer_tcp_flags l3_metadata.lkp_tcp_flags
#endif /* !TUNNEL_PARSING_DISABLE */

#ifdef IPV6_DISABLE
@pragma pa_alias ingress l3_metadata.lkp_ip_version ipv4.version
#endif
#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
@pragma pa_solitary egress l3_metadata.outer_routed
#endif
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma pa_solitary ingress l3_metadata.lkp_ip_ttl
@pragma pa_container_size ingress l3_metadata.lkp_ip_ttl 8
#endif
#ifndef __p4c__
#if defined(GENERIC_INT_LEAF_PROFILE)
@pragma pa_container_size ingress l3_metadata.nexthop_index 32
#endif
#endif
#if defined(GENERIC_INT_SPINE_PROFILE)
@pragma pa_container_size ingress l3_metadata.fib_hit 8
@pragma pa_container_size ingress l3_metadata.fib_nexthop_type 8
#endif
#if defined(GENERIC_INT_LEAF_PROFILE) || defined(MSDC_LEAF_DTEL_INT_PROFILE) \
    || defined(ENT_FIN_POSTCARD_PROFILE)
@pragma pa_container_size egress l3_metadata.outer_routed 32
#endif
#if defined(MSDC_LEAF_DTEL_INT_PROFILE) || defined(MSDC_SPINE_DTEL_INT_PROFILE)
@pragma pa_container_size ingress l3_metadata.rocev2_dst_qp_plus_rsvd 32
@pragma pa_container_size ingress l3_metadata.rocev2_opcode 32
@pragma pa_container_size ingress l3_metadata.rocev2_aeth_syndrome 32
#endif
#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(L3_HEAVY_INT_SPINE_PROFILE)
@pragma pa_container_size ingress l3_metadata.fib_hit 16
@pragma pa_container_size ingress l3_metadata.fib_hit_myip 16
#endif
#if defined(MSDC_IPV4_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma pa_solitary ingress l3_metadata.fib_nexthop_type
@pragma pa_solitary ingress l3_metadata.fib_nexthop
#endif
#if defined(MSDC_IPV4_PROFILE)
@pragma pa_container_size ingress l3_metadata.rmac_group 8
#endif
#if defined(M0_PROFILE)
@pragma pa_container_size ingress l3_metadata.fib_hit_myip 8
#endif
metadata l3_metadata_t l3_metadata;

/*****************************************************************************/
/* Validate outer IP header                                                */
/*****************************************************************************/
#ifdef ALT_IP_PKT_VALIDATE_ENABLE
table validate_outer_ip_packet {
    reads {
        ig_intr_md_from_parser_aux.ingress_parser_err mask 0x1000 : ternary;
        ipv4 : valid;
        ipv6 : valid;
        ipv4.ihl: ternary;
#if !defined(IPV4_L2_MULTICAST_DISABLE) || !defined(IPV4_L3_MULTICAST_DISABLE)
        ipv4.dstAddr mask 0xFFFFFF00 : ternary;
#endif /* !defined(IPV4_L2_MULTICAST_DISABLE) || !defined(IPV4_L3_MULTICAST_DISABLE) */
#if !defined(IPV6_L2_MULTICAST_DISABLE) || !defined(IPV6_L3_MULTICAST_DISABLE)
        ipv6.dstAddr mask 0xFFFF0000000000000000000000000000 : ternary;
#endif /* !defined(IPV6_L2_MULTICAST_DISABLE) || !defined(IPV6_L3_MULTICAST_DISABLE) */
#ifdef IP_TYPE_EXTENSION_ENABLE
        ipv4_option_32b : valid;
#endif
    }
    actions {
        set_valid_outer_ipv4_packet;
#if !defined(IPV4_L3_MULTICAST_DISABLE)
        set_valid_outer_ipv4_llmc_packet;
#endif /* !defined(IPV4_L3_MULTICAST_DISABLE) */
#ifdef IP_TYPE_EXTENSION_ENABLE
        set_validate_outer_ipv4_packet_with_option;
#endif
#if !defined(IPV4_L2_MULTICAST_DISABLE) || !defined(IPV4_L3_MULTICAST_DISABLE)
        set_valid_outer_ipv4_llmc_packet;
        set_valid_outer_ipv4_mc_packet;
#endif /* !defined(IPV4_L2_MULTICAST_DISABLE) || !defined(IPV4_L3_MULTICAST_DISABLE) */
        set_malformed_outer_ipv4_packet;
        set_valid_outer_ipv6_packet;
#if !defined(IPV6_L2_MULTICAST_DISABLE) || !defined(IPV6_L3_MULTICAST_DISABLE)
        set_valid_outer_ipv6_llmc_packet;
        set_valid_outer_ipv6_mc_packet;
#endif /* !defined(IPV6_L2_MULTICAST_DISABLE) || !defined(IPV6_L3_MULTICAST_DISABLE) */
        set_malformed_outer_ipv6_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control validate_outer_ip_header {
    apply(validate_outer_ip_packet);
}
#endif /* ALT_IP_PKT_VALIDATE_ENABLE */

/*****************************************************************************/
/* Router MAC lookup                                                         */
/*****************************************************************************/
action rmac_hit() {
    modify_field(l3_metadata.rmac_hit, TRUE);
}

action rmac_miss() {
    modify_field(l3_metadata.rmac_hit, FALSE);
}

#if defined(L2_PROFILE) || defined(Q0_PROFILE)
@pragma ternary 1
#endif
table rmac {
    reads {
        l3_metadata.rmac_group : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
        rmac_hit;
        rmac_miss;
    }
    size : ROUTER_MAC_TABLE_SIZE;
}


/*****************************************************************************/
/* FIB hit actions for nexthops and ECMP                                     */
/*****************************************************************************/
#ifdef SYSTEM_FLOW_ACL_ENABLE
#define FIB_ACTIONS \
        on_miss; \
        fib_hit_nexthop; \
        fib_hit_ecmp; \
        fib_redirect_to_cpu;
#else
#define FIB_ACTIONS \
        on_miss; \
        fib_hit_nexthop; \
        fib_hit_ecmp; \
        fib_hit_myip;
#endif /* SYSTEM_FLOW_ACL_ENABLE */ \

#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
action fib_hit_nexthop(nexthop_index, acl_label) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(l3_metadata.routed, TRUE);
#ifdef FIB_LABEL_ENABLE
    modify_field(l3_metadata.fib_label, acl_label);
#endif /* FIB_LABEL_ENABLE */
}

action fib_hit_myip(nexthop_index, acl_label) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(l3_metadata.fib_hit_myip, TRUE);
#ifdef FIB_LABEL_ENABLE
    modify_field(l3_metadata.fib_label, acl_label);
#endif /* FIB_LABEL_ENABLE */
}

action fib_hit_ecmp(ecmp_index, acl_label) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.nexthop_index, ecmp_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_ECMP);
    modify_field(l3_metadata.routed, TRUE);
#ifdef FIB_LABEL_ENABLE
    modify_field(l3_metadata.fib_label, acl_label);
#endif /* FIB_LABEL_ENABLE */
}

#else
action fib_hit_nexthop(nexthop_index, acl_label) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_SIMPLE);
#ifdef FIB_LABEL_ENABLE
    modify_field(l3_metadata.fib_label, acl_label);
#endif /* FIB_LABEL_ENABLE */
}

action fib_hit_myip(nexthop_index, acl_label) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(l3_metadata.fib_hit_myip, TRUE);
#ifdef FIB_LABEL_ENABLE
    modify_field(l3_metadata.fib_label, acl_label);
#endif /* FIB_LABEL_ENABLE */
}

action fib_hit_ecmp(ecmp_index, acl_label) {
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l3_metadata.fib_nexthop, ecmp_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_ECMP);
#ifdef FIB_LABEL_ENABLE
    modify_field(l3_metadata.fib_label, acl_label);
#endif /* FIB_LABEL_ENABLE */
}
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */

action fib_redirect_to_cpu(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
}


#if !defined(URPF_DISABLE)
/*****************************************************************************/
/* uRPF BD check                                                             */
/*****************************************************************************/
action urpf_bd_miss() {
    modify_field(l3_metadata.urpf_check_fail, TRUE);
}

action urpf_miss() {
    modify_field(l3_metadata.urpf_check_fail, TRUE);
}

table urpf_bd {
    reads {
        l3_metadata.urpf_bd_group : exact;
        ingress_metadata.bd : exact;
    }
    actions {
        nop;
        urpf_bd_miss;
    }
    size : URPF_GROUP_TABLE_SIZE;
}
#endif /* URPF_DISABLE */

control process_urpf_bd {
#if !defined(URPF_DISABLE)
    if ((l3_metadata.urpf_mode == URPF_MODE_STRICT) and
        (l3_metadata.urpf_hit == TRUE)) {
        apply(urpf_bd);
    }
#endif /* URPF_DISABLE */
}


/*****************************************************************************/
/* Egress L3 rewrite                                                         */
/*****************************************************************************/
action rewrite_smac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table smac_rewrite {
    reads {
        egress_metadata.smac_idx : exact;
    }
    actions {
        rewrite_smac;
    }
    size : MAC_REWRITE_TABLE_SIZE;
}


action ipv4_unicast_rewrite() {
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
    add_to_field(ipv4.ttl, -1);
}

action ipv4_multicast_rewrite() {
    add_to_field(ipv4.ttl, -1);
}

action ipv6_unicast_rewrite() {
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
    add_to_field(ipv6.hopLimit, -1);
}

action ipv6_multicast_rewrite() {
    add_to_field(ipv6.hopLimit, -1);
}

action mpls_rewrite() {
    modify_field(ethernet.dstAddr, egress_metadata.mac_da);
    add_to_field(mpls[0].ttl, -1);
}

table l3_rewrite {
    reads {
        ipv4 : valid;
#ifndef IPV6_DISABLE
        ipv6 : valid;
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
        mpls[0] : valid;
#endif /* MPLS_DISABLE */
        ipv4.dstAddr mask 0xF0000000 : ternary;
#ifndef IPV6_DISABLE
        ipv6.dstAddr mask 0xFF000000000000000000000000000000 : ternary;
#endif /* IPV6_DISABLE */
    }
    actions {
        nop;
        ipv4_unicast_rewrite;
#ifndef L3_MULTICAST_DISABLE
        ipv4_multicast_rewrite;
#endif /* L3_MULTICAST_DISABLE */
#ifndef IPV6_DISABLE
        ipv6_unicast_rewrite;
#ifndef L3_MULTICAST_DISABLE
        ipv6_multicast_rewrite;
#endif /* L3_MULTICAST_DISABLE */
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
        mpls_rewrite;
#endif /* MPLS_DISABLE */
    }
}

control process_mac_rewrite {
#if !defined(L3_DISABLE) || !defined(MPLS_DISABLE)
    if (egress_metadata.routed == TRUE) {
        apply(l3_rewrite);
        apply(smac_rewrite);
    }
#endif /* L3_DISABLE || MPLS_DISABLE */
}


/*****************************************************************************/
/* Egress MTU check                                                          */
/*****************************************************************************/
#if !defined(L3_DISABLE)
action ipv4_mtu_check(l3_mtu_plus_one) {
    subtract(l3_metadata.l3_mtu_check, l3_mtu_plus_one, ipv4.totalLen);
}

action ipv6_mtu_check(l3_mtu_plus_one) {
    subtract(l3_metadata.l3_mtu_check, l3_mtu_plus_one, ipv6.payloadLen);
}

action mtu_miss() {
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
}

#if !defined(L3_HEAVY_INT_LEAF_PROFILE) && !defined(Q0_PROFILE)
@pragma ternary 1
#endif
#if defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 10
#endif
table mtu {
    reads {
        l3_metadata.mtu_index : exact;
        ipv4 : valid;
        ipv6 : valid;
    }
    actions {
        mtu_miss;
        ipv4_mtu_check;
#ifndef IPV6_DISABLE
        ipv6_mtu_check;
#endif
    }
    size : L3_MTU_TABLE_SIZE;
}
#endif /* L3_DISABLE */

control process_mtu {
#if !defined(L3_DISABLE)
    apply(mtu);
#endif /* L3_DISABLE */
}
