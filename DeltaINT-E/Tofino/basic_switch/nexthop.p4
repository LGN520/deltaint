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
 * Nexthop related processing
 */

/*
 * nexthop metadata
 */
#ifdef __p4c__
@pragma pa_no_overlay ingress nexthop_metadata.nexthop_type
#endif
header_type nexthop_metadata_t {
    fields {
        nexthop_type : 1;                        /* final next hop index type */
        nexthop_glean : 1;                       /* Glean adjacency */
#ifdef TRANSIENT_LOOP_PREVENTION
        nexthop_offset : 8;			 /* Offset next group */
#endif
    }
}

#ifdef ENT_DC_GENERAL_PROFILE
@pragma pa_container_size ingress ig_intr_md_for_tm.disable_ucast_cutthru 8
#endif /* ENT_DC_GENERAL_PROFILE */
#ifdef MSDC_IPV4_PROFILE
@pragma pa_container_size ingress ig_intr_md_for_tm.disable_ucast_cutthru 8
@pragma pa_container_size ingress nexthop_metadata.nexthop_glean 8
#endif /* MSDC_IPV4_PROFILE */

metadata nexthop_metadata_t nexthop_metadata;

/*****************************************************************************/
/* Forwarding result lookup and decisions                                    */
/*****************************************************************************/
#ifndef FWD_RESULTS_OPTIMIZATION_ENABLE
#if defined(L2_TUNNEL_ENABLE)
action set_l2_redirect() {
    modify_field(nexthop_metadata.nexthop_type, l2_metadata.l2_nexthop_type);
    modify_field(ingress_metadata.egress_ifindex, 0);
    invalidate(ig_intr_md_for_tm.mcast_grp_b);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action set_l2_redirect_base() {
    modify_field(l3_metadata.nexthop_index, l2_metadata.l2_nexthop);
    set_l2_redirect();
}
#endif /* L2_TUNNEL_ENABLE */

action set_acl_redirect() {
#ifdef RACL_DISABLE
    modify_field(nexthop_metadata.nexthop_type, acl_metadata.acl_nexthop_type);
    modify_field(ingress_metadata.egress_ifindex, 0);
    invalidate(ig_intr_md_for_tm.mcast_grp_b);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
#endif /* RACL_DISABLE */
}

action set_acl_redirect_base() {
#ifdef RACL_DISABLE
    modify_field(l3_metadata.nexthop_index, acl_metadata.acl_nexthop);
    set_acl_redirect();
#endif /* RACL_DISABLE */
}

action set_racl_redirect() {
    modify_field(nexthop_metadata.nexthop_type, acl_metadata.racl_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
    modify_field(ingress_metadata.egress_ifindex, 0);
    invalidate(ig_intr_md_for_tm.mcast_grp_b);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action set_racl_redirect_base() {
    modify_field(l3_metadata.nexthop_index, acl_metadata.racl_nexthop);
    set_racl_redirect();
}

action set_fib_redirect() {
    modify_field(nexthop_metadata.nexthop_type, l3_metadata.fib_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
    invalidate(ig_intr_md_for_tm.mcast_grp_b);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action set_fib_redirect_base() {
    modify_field(l3_metadata.nexthop_index, l3_metadata.fib_nexthop);
    set_fib_redirect();
}

action set_nat_redirect() {
    modify_field(nexthop_metadata.nexthop_type, nat_metadata.nat_nexthop_type);
    modify_field(l3_metadata.routed, TRUE);
    invalidate(ig_intr_md_for_tm.mcast_grp_b);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action set_nat_redirect_base() {
    modify_field(l3_metadata.nexthop_index, nat_metadata.nat_nexthop);
    set_nat_redirect();
}

#ifdef TRANSIENT_LOOP_PREVENTION
action set_l2_redirect_offset() {
    add(l3_metadata.nexthop_index, l2_metadata.l2_nexthop, nexthop_metadata.nexthop_offset);
    set_l2_redirect();
}

action set_acl_redirect_offset() {
#ifdef RACL_DISABLE
    add(l3_metadata.nexthop_index, acl_metadata.acl_nexthop, nexthop_metadata.nexthop_offset);
    set_acl_redirect();
#endif /* RACL_DISABLE */
}

action set_racl_redirect_offset() {
    add(l3_metadata.nexthop_index, acl_metadata.racl_nexthop, nexthop_metadata.nexthop_offset);
    set_racl_redirect();
}

action set_fib_redirect_offset() {
    add(l3_metadata.nexthop_index, l3_metadata.fib_nexthop, nexthop_metadata.nexthop_offset);
    set_fib_redirect();
}

action set_nat_redirect_offset() {
    add(l3_metadata.nexthop_index, nat_metadata.nat_nexthop, nexthop_metadata.nexthop_offset);
    set_nat_redirect();
}
#endif

action set_cpu_redirect(cpu_ifindex) {
    modify_field(l3_metadata.routed, FALSE);
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(ingress_metadata.egress_port_lag_index, cpu_ifindex);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action set_rmac_non_ip_drop() {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, DROP_RMAC_HIT_NON_IP);
}

action set_multicast_route() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
    modify_field(ig_intr_md_for_tm.mcast_grp_b,
                 multicast_metadata.multicast_route_mc_index);
    modify_field(l3_metadata.routed, TRUE);
    modify_field(l3_metadata.same_bd_check, 0xFFFF);
}

action set_multicast_rpf_fail_bridge() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
    modify_field(ig_intr_md_for_tm.mcast_grp_b,
                 multicast_metadata.multicast_bridge_mc_index);
    modify_field(multicast_metadata.mcast_rpf_fail, TRUE);
}

action set_multicast_rpf_fail_flood_to_mrouters() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
    modify_field(multicast_metadata.mcast_rpf_fail, TRUE);
    modify_field(multicast_metadata.flood_to_mrouters, TRUE);
}

action set_multicast_bridge() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
    modify_field(ig_intr_md_for_tm.mcast_grp_b,
                 multicast_metadata.multicast_bridge_mc_index);
}

action set_multicast_rpf_fail_flood() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
    modify_field(multicast_metadata.mcast_rpf_fail, TRUE);
}

action set_multicast_miss_flood() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
}

action set_multicast_drop() {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, DROP_MULTICAST_SNOOPING_ENABLED);
}

action set_multicast_miss_flood_to_mrouters() {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
    modify_field(multicast_metadata.flood_to_mrouters, TRUE);
}

action set_cpu_tx_flood() {
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
}

#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma stage 6
#endif
table fwd_result {
    reads {
#if defined(L2_TUNNEL_ENABLE)
        l2_metadata.l2_redirect : ternary;
#endif /* L2_TUNNEL_ENABLE */
#ifdef RACL_DISABLE
        acl_metadata.acl_redirect : ternary;
#else
        acl_metadata.racl_redirect : ternary;
#endif /* RACL_DISABLE */
        l3_metadata.rmac_hit : ternary;
        l3_metadata.fib_hit : ternary;
#ifndef NAT_DISABLE
        nat_metadata.nat_hit : ternary;
#endif /* NAT_DISABLE */
        l2_metadata.lkp_pkt_type : ternary;
        l3_metadata.lkp_ip_type : ternary;
#if !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE)
        multicast_metadata.igmp_snooping_enabled : ternary;
#ifndef IPV6_DISABLE
        multicast_metadata.mld_snooping_enabled : ternary;
#endif /* IPV6_DISABLE */
        multicast_metadata.mcast_route_hit : ternary;
        multicast_metadata.mcast_bridge_hit : ternary;
        multicast_metadata.mcast_rpf_group : ternary;
        multicast_metadata.mcast_mode : ternary;
        l3_metadata.lkp_ip_llmc : ternary;
        l3_metadata.lkp_ip_mc : ternary;
#endif /* !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE) */
        // only for ecmp group add
#ifdef TRANSIENT_LOOP_PREVENTION
        l2_metadata.l2_nexthop_type : ternary;
        l3_metadata.fib_nexthop_type : ternary;
        acl_metadata.acl_nexthop_type : ternary;
#endif TRANSIENT_LOOP_PREVENTION
        ingress_metadata.drop_flag : ternary;
        ingress_metadata.port_type : ternary;
        ingress_metadata.bypass_lookups : ternary;
    }
    actions {
        nop;
#if defined(L2_TUNNEL_ENABLE)
        set_l2_redirect_base;
#endif /* L2_TUNNEL_ENABLE */
        set_fib_redirect_base;
        set_cpu_redirect;
        set_acl_redirect_base;
#ifndef RACL_DISABLE
        set_racl_redirect_base;
#endif
#ifdef TRANSIENT_LOOP_PREVENTION
#if defined(L2_TUNNEL_ENABLE)
        set_l2_redirect_offset;
#endif /* L2_TUNNEL_ENABLE */
        set_fib_redirect_offset;
        set_acl_redirect_offset;
#endif /* TRANSIENT_LOOP_PREVENTION */
	set_rmac_non_ip_drop;
#ifndef NAT_DISABLE
        set_nat_redirect_base;
#endif /* NAT_DISABLE */
#if !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE)
        set_multicast_route;
        set_multicast_rpf_fail_bridge;
        set_multicast_rpf_fail_flood_to_mrouters;
        set_multicast_rpf_fail_flood;
        set_multicast_bridge;
        set_multicast_miss_flood;
        set_multicast_miss_flood_to_mrouters;
        set_multicast_drop;
#endif /* !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE) */
        set_cpu_tx_flood;
    }
    size : FWD_RESULT_TABLE_SIZE;
}

control process_fwd_results {
    if (not(BYPASS_ALL_LOOKUPS)) {
        apply(fwd_result);
    }
}
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */

/*****************************************************************************/
/* ECMP lookup                                                               */
/*****************************************************************************/
#ifdef TRANSIENT_LOOP_PREVENTION
action select_ecmp_nexthop(port_lag_index, nhop_index) {
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
    modify_field(l3_metadata.nexthop_index, nhop_index);
}
#else
/*
 * If dest mac is not know, then unicast packet needs to be flooded in
 * egress BD
 */
action set_ecmp_nexthop_details_for_post_routed_flood(bd, uuc_mc_index,
                                                      nhop_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_b, uuc_mc_index);
    modify_field(l3_metadata.nexthop_index, nhop_index);
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action set_ecmp_nexthop_details(ifindex, port_lag_index, bd, nhop_index) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
    modify_field(l3_metadata.nexthop_index, nhop_index);
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
    bit_xor(l2_metadata.same_if_check, ingress_metadata.ifindex, ifindex);
}

#if !defined(TUNNEL_DISABLE) || defined(L3_HEAVY_INT_LEAF_PROFILE)
action set_ecmp_nexthop_details_with_tunnel(bd, tunnel_dst_index, tunnel) {
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
#ifndef TUNNEL_SAME_IF_CHECK_DISABLE
    bit_xor(tunnel_metadata.tunnel_if_check,
            tunnel_metadata.tunnel_terminate, tunnel);
#endif
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(ingress_metadata.egress_ifindex, 0x0);
    bit_and(ig_intr_md_for_tm.disable_ucast_cutthru, l2_metadata.non_ip_packet, TRUE);
}
#endif /* TUNNEL_DISABLE */

action set_ecmp_nexthop_details_for_redirect_to_cpu(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
}
#endif

action set_wcmp() {
}

field_list l3_hash_fields {
#if defined(RESILIENT_HASH_ENABLE)
#ifndef HASH_32BIT_ENABLE
    hash_metadata.hash2;
    hash_metadata.hash1;
#endif
    hash_metadata.hash2;
#endif /* RESILIENT_HASH_ENABLE */
    hash_metadata.hash1;
#ifdef FLOWLET_ENABLE
    flowlet_metadata.id;
#endif /* FLOWLET_ENABLE */
}

field_list_calculation ecmp_hash {
    input {
        l3_hash_fields;
    }
#if defined(RESILIENT_HASH_ENABLE)
    algorithm {
	identity;
	crc_64;
    }
    output_width : 52;
#elif defined(FLOWLET_ENABLE)
    algorithm {
	crc_16;
	identity;
    }
    output_width : 14;
#else
    algorithm {
    	identity;
	crc_16_dect;
    }
    output_width : 14;
#endif /* RESILIENT_HASH_ENABLE */
}

action_selector ecmp_selector {
    selection_key : ecmp_hash;
#ifdef RESILIENT_HASH_ENABLE
    selection_mode : resilient;
#else
    selection_mode : fair;
#endif /* RESILIENT_HASH_ENABLE */
}

action_profile ecmp_action_profile {
    actions {
#ifdef TRANSIENT_LOOP_PREVENTION
        select_ecmp_nexthop;
#else
        nop;
        set_ecmp_nexthop_details;
#if !defined(TUNNEL_DISABLE) || defined(L3_HEAVY_INT_LEAF_PROFILE)
        set_ecmp_nexthop_details_with_tunnel;
#endif /* TUNNEL_DISABLE */
        set_ecmp_nexthop_details_for_post_routed_flood;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        set_ecmp_nexthop_details_for_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
#endif
#ifdef WCMP_ENABLE
        set_wcmp;
#endif /* WCMP_ENABLE */
    }
    size : ECMP_SELECT_TABLE_SIZE;
    dynamic_action_selection : ecmp_selector;
}

#ifdef TRANSIENT_LOOP_PREVENTION
@pragma selector_num_max_groups ECMP_GROUP_TABLE_SIZE
#endif 
table ecmp_group {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    action_profile: ecmp_action_profile;
    size : ECMP_GROUP_TABLE_SIZE;
}

/*****************************************************************************/
/* WCMP lookup                                                               */
/*****************************************************************************/
#ifdef WCMP_ENABLE
action set_wcmp_nexthop_details(ifindex, port_lag_index, bd, nhop_index, tunnel) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
    modify_field(l3_metadata.nexthop_index, nhop_index);
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
    bit_xor(l2_metadata.same_if_check, l2_metadata.same_if_check, ifindex);
}

table wcmp_group {
    reads {
        l3_metadata.nexthop_index : exact;
        hash_metadata.hash1 mask 0x00ff : range;
    }
    actions {
        set_wcmp_nexthop_details;
    }
    size : WCMP_GROUP_TABLE_SIZE;
}
#endif /* WCMP_ENABLE */

/*****************************************************************************/
/* Nexthop lookup                                                            */
/*****************************************************************************/
/*
 * If dest mac is not know, then unicast packet needs to be flooded in
 * egress BD
 */
action set_nexthop_details_for_post_routed_flood(bd, uuc_mc_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_b, uuc_mc_index);
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(ingress_metadata.egress_port_lag_index, 0);
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

#if !defined(TUNNEL_DISABLE) || defined(L3_HEAVY_INT_LEAF_PROFILE)
action set_nexthop_details_with_tunnel(bd, tunnel_dst_index, tunnel) {
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
#ifndef TUNNEL_SAME_IF_CHECK_DISABLE
    bit_xor(tunnel_metadata.tunnel_if_check,
            tunnel_metadata.tunnel_terminate, tunnel);
#endif
    bit_and(ig_intr_md_for_tm.disable_ucast_cutthru, l2_metadata.non_ip_packet, TRUE);
    modify_field(tunnel_metadata.tunnel_dst_index, tunnel_dst_index);
    modify_field(ingress_metadata.egress_ifindex, 0x0);
#ifdef SRV6_ENABLE
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_SRV6_L3VPN);
#endif
}
#endif /* TUNNEL_DISABLE */

action set_nexthop_details_for_glean(ifindex) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(nexthop_metadata.nexthop_glean, TRUE);
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, 0x3FFF);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
}

action set_nexthop_details_for_drop() {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, DROP_NHOP);
}

action set_nexthop_details_for_redirect_to_cpu(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
}


#ifdef TRANSIENT_LOOP_PREVENTION
action set_nexthop_details(ifindex, bd) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
    bit_xor(l2_metadata.same_if_check, l2_metadata.same_if_check, ifindex);
}

table nexthop_details {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_nexthop_details;
#if !defined(TUNNEL_DISABLE) || defined(L3_HEAVY_INT_LEAF_PROFILE)
        set_nexthop_details_with_tunnel;
#endif /* TUNNEL_DISABLE */
        set_nexthop_details_for_post_routed_flood;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        set_nexthop_details_for_redirect_to_cpu;
#else
	set_nexthop_details_for_glean;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
        set_nexthop_details_for_drop;
    }
    default_action: nop;
    size : NEXTHOP_TABLE_SIZE;
}

action set_nexthop_port_lag(port_lag_index) {
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
}

table nexthop {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_nexthop_port_lag;
    }
    default_action: nop;
    size : NEXTHOP_TABLE_SIZE;
}
#else
action set_nexthop_details(ifindex, port_lag_index, bd) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
    bit_xor(l3_metadata.same_bd_check, ingress_metadata.bd, bd);
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
    bit_xor(l2_metadata.same_if_check, l2_metadata.same_if_check, ifindex);
}

#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma stage 8
#endif
table nexthop {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_nexthop_details;
#if !defined(TUNNEL_DISABLE) || defined(L3_HEAVY_INT_LEAF_PROFILE)
        set_nexthop_details_with_tunnel;
#endif /* TUNNEL_DISABLE */
        set_nexthop_details_for_post_routed_flood;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        set_nexthop_details_for_redirect_to_cpu;
#elif !defined(NEXTHOP_GLEAN_OPTIMIZATION_ENABLE)
	    set_nexthop_details_for_glean;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
        set_nexthop_details_for_drop;
    }
    size : NEXTHOP_TABLE_SIZE;
}
#endif

#ifdef TRANSIENT_LOOP_PREVENTION
register ttl_eval {
    width : 8;
    instance_count : 1;
}

 blackbox stateful_alu ttl_4 {
    reg : ttl_eval;
    condition_lo: ipv4.ttl >= 4;
    update_lo_1_predicate: condition_lo;
    update_lo_1_value : 4;
    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: ipv4.ttl;
    output_predicate : 1;
    output_value : alu_lo;
    output_dst: ipv4.ttl;
}

action set_ttl_4() {
    ttl_4.execute_stateful_alu(0);
}

action ttl4_drop() {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, DROP_TTL4);
}

table ttl4_set {
    reads {
       ipv4.ttl : exact;
    }
    actions {
        nop;        // do nothing
        set_ttl_4;  // force TTL to 4, if >=4
        ttl4_drop;  // drop for ttl < 4
    }
    default_action: nop;
    // set default action to set_ttl_4 to enable ttl4 processing
    // entries {0..3} => ttl4_drop (program from runtime)
    size : 64;
}
#endif

control process_nexthop {
    if (nexthop_metadata.nexthop_type == NEXTHOP_TYPE_ECMP) {
#ifdef FAST_FAILOVER_ENABLE
        if (valid(pktgen_recirc)) {
            apply(ecmp_failover);
            apply(ecmp_failover_recirc);
        } else {
#endif
        /* resolve ecmp */
#ifdef WCMP_ENABLE
            apply(ecmp_group) {
                set_wcmp {
                    /* resolve wcmp */
                    apply(wcmp_group);
                }
            }
#else
            apply(ecmp_group);
#endif /* WCMP_ENABLE */
#ifdef TRANSIENT_LOOP_PREVENTION
            if(valid(ipv4) and (nexthop_metadata.nexthop_offset != 0)) {
                apply(ttl4_set);
            }
#endif
#ifdef FAST_FAILOVER_ENABLE
        }
#endif /* FAST_FAILOVER_ENABLE */

    } else {
        /* resolve nexthop */
        apply(nexthop);
    }
}
