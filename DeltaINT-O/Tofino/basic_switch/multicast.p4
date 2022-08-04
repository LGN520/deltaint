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
 * Multicast processing
 */

header_type multicast_metadata_t {
    fields {
        ipv4_mcast_key_type : 1;               /* 0 bd, 1 vrf */
        ipv4_mcast_key : BD_BIT_WIDTH;         /* bd or vrf value */
        ipv6_mcast_key_type : 1;               /* 0 bd, 1 vrf */
        ipv6_mcast_key : BD_BIT_WIDTH;         /* bd or vrf value */
        outer_mcast_route_hit : 1;             /* hit in the outer multicast table */
        outer_mcast_mode : 2;                  /* multicast mode from route */
        mcast_route_hit : 1;                   /* hit in the multicast route table */
        mcast_route_s_g_hit : 1;               /* hit in the multicast S,G route table */
        mcast_bridge_hit : 1;                  /* hit in the multicast bridge table */
        mcast_copy_to_cpu : 1;                 /* copy to cpu flag */
        ipv4_multicast_enabled : 1;            /* is ipv4 multicast enabled on BD */
        ipv6_multicast_enabled : 1;            /* is ipv6 multicast enabled on BD */
        igmp_snooping_enabled : 1;             /* is IGMP snooping enabled on BD */
        mld_snooping_enabled : 1;              /* is MLD snooping enabled on BD */
        bd_mrpf_group : BD_BIT_WIDTH;          /* rpf group from bd lookup */
        mcast_rpf_group : BD_BIT_WIDTH;        /* rpf group from mcast lookup */
        mcast_rpf_fail : 1;                    /* RPF check failed */
        flood_to_mrouters : 1;                  /* Flood to router ports only */
        mcast_mode : 2;                        /* multicast mode from route */
        multicast_route_mc_index : 16;         /* multicast index from mfib */
        multicast_bridge_mc_index : 16;        /* multicast index from igmp/mld snoop */
        inner_replica : 1;                     /* is copy is due to inner replication */
        replica : 1;                           /* is this a replica */
#ifdef FABRIC_ENABLE
        mcast_grp_a : 16;
        mcast_grp_b : 16;
        ingress_rid : 16;
        l1_exclusion_id : 16;
#endif /* FABRIC_ENABLE */
    }
}

#ifndef MULTICAST_DISABLE
@pragma pa_solitary ingress multicast_metadata.multicast_route_mc_index
@pragma pa_atomic ingress multicast_metadata.multicast_route_mc_index
@pragma pa_solitary ingress multicast_metadata.multicast_bridge_mc_index
@pragma pa_atomic ingress multicast_metadata.multicast_bridge_mc_index
#endif /* MULTICAST_DISABLE */
#if !defined(FABRIC_PROFILE)
/* This field is part of bridged metadata.  The fabric
   profile puts a lot of pressure on 16-bit containers.
   Even though the natural container size of this field is 16,
   it can safely be allocated in a 32-bit container based
   on the packing constraints of the egress instance of
   fabric_header_multicast. */
//@pragma pa_container_size ingress ig_intr_md_for_tm.mcast_grp_a 16
#endif
#if defined(GENERIC_INT_SPINE_PROFILE)
@pragma pa_container_size ingress multicast_metadata.mcast_route_hit 8
#endif
metadata multicast_metadata_t multicast_metadata;

/*****************************************************************************/
/* Outer IP multicast RPF check                                              */
/*****************************************************************************/
#if !defined(TUNNEL_MULTICAST_DISABLE)
action outer_multicast_rpf_check_pass() {
    modify_field(tunnel_metadata.tunnel_lookup, TRUE);
    modify_field(l3_metadata.outer_routed, TRUE);
}

table outer_multicast_rpf {
    reads {
        multicast_metadata.mcast_rpf_group : exact;
        multicast_metadata.bd_mrpf_group : exact;
    }
    actions {
        nop;
        outer_multicast_rpf_check_pass;
    }
    size : OUTER_MCAST_RPF_TABLE_SIZE;
}
#endif /* !TUNNEL_MULTICAST_DISABLE */

control process_outer_multicast_rpf {
#if !defined(OUTER_PIM_BIDIR_OPTIMIZATION)
    /* outer mutlicast RPF check - sparse and bidir */
    if (multicast_metadata.outer_mcast_route_hit == TRUE) {
        apply(outer_multicast_rpf);
    }
#endif /* !OUTER_PIM_BIDIR_OPTIMIZATION */
}


/*****************************************************************************/
/* Outer IP mutlicast lookup actions                                         */
/*****************************************************************************/
#if !defined(TUNNEL_MULTICAST_DISABLE)
#if !defined(OUTER_MULTICAST_BRIDGE_DISABLE)
action outer_multicast_bridge_star_g_hit(mc_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, mc_index);
    modify_field(tunnel_metadata.tunnel_lookup, TRUE);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action outer_multicast_bridge_s_g_hit(mc_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, mc_index);
    modify_field(tunnel_metadata.tunnel_lookup, TRUE);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */

action outer_multicast_route_sm_star_g_hit(mc_index, mcast_rpf_group) {
    modify_field(multicast_metadata.outer_mcast_mode, MCAST_MODE_SM);
    modify_field(ig_intr_md_for_tm.mcast_grp_a, mc_index);
    modify_field(multicast_metadata.outer_mcast_route_hit, TRUE);
    bit_xor(multicast_metadata.mcast_rpf_group, mcast_rpf_group,
            multicast_metadata.bd_mrpf_group);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action outer_multicast_route_bidir_star_g_hit(mc_index, mcast_rpf_group) {
    modify_field(multicast_metadata.outer_mcast_mode, MCAST_MODE_BIDIR);
    modify_field(ig_intr_md_for_tm.mcast_grp_a, mc_index);
    modify_field(multicast_metadata.outer_mcast_route_hit, TRUE);
#ifdef OUTER_PIM_BIDIR_OPTIMIZATION
    bit_or(multicast_metadata.mcast_rpf_group, mcast_rpf_group,
           multicast_metadata.bd_mrpf_group);
#else
    modify_field(multicast_metadata.mcast_rpf_group, mcast_rpf_group);
#endif
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action outer_multicast_route_s_g_hit(mc_index, mcast_rpf_group) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, mc_index);
    modify_field(multicast_metadata.outer_mcast_route_hit, TRUE);
    bit_xor(multicast_metadata.mcast_rpf_group, mcast_rpf_group,
            multicast_metadata.bd_mrpf_group);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}
#endif /* !TUNNEL_MULTICAST_DISABLE */


/*****************************************************************************/
/* Outer IPv4 multicast lookup                                               */
/*****************************************************************************/
#if !defined(IPV4_TUNNEL_MULTICAST_DISABLE)
table outer_ipv4_multicast_star_g {
    reads {
#ifdef OUTER_MULTICAST_BRIDGE_DISABLE
        l3_metadata.vrf : exact;
#else
        multicast_metadata.ipv4_mcast_key_type : exact;
        multicast_metadata.ipv4_mcast_key : exact;
#endif /* OUTER_MULTICAST_BRIDGE_DISABLE */
        ipv4.dstAddr : ternary;
    }
    actions {
        nop;
        outer_multicast_route_sm_star_g_hit;
        outer_multicast_route_bidir_star_g_hit;
#if !defined(OUTER_MULTICAST_BRIDGE_DISABLE)
        outer_multicast_bridge_star_g_hit;
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */
    }
    size : OUTER_MULTICAST_STAR_G_TABLE_SIZE;
}

@pragma ternary 1
table outer_ipv4_multicast {
    reads {
#ifdef OUTER_MULTICAST_BRIDGE_DISABLE
        l3_metadata.vrf : exact;
#else
        multicast_metadata.ipv4_mcast_key_type : exact;
        multicast_metadata.ipv4_mcast_key : exact;
#endif /* OUTER_MULTICAST_BRIDGE_DISABLE */
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
    }
    actions {
        nop;
        on_miss;
        outer_multicast_route_s_g_hit;
#if !defined(OUTER_MULTICAST_BRIDGE_DISABLE)
        outer_multicast_bridge_s_g_hit;
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */
    }
    size : OUTER_MULTICAST_S_G_TABLE_SIZE;
}
#endif /* !IPV4_TUNNEL_MULTICAST_DISABLE */

control process_outer_ipv4_multicast {
#if !defined(IPV4_TUNNEL_MULTICAST_DISABLE)
    /* check for ipv4 multicast tunnel termination  */

#ifdef OUTER_MULTICAST_BRIDGE_DISABLE
  if (multicast_metadata.ipv4_multicast_enabled==1) {
# else
    {
#endif /* OUTER_MULTICAST_BRIDGE_DISABLE */
      apply(outer_ipv4_multicast) {
        on_miss {
	  apply(outer_ipv4_multicast_star_g);
        }
      }
    }
#endif /* !IPV4_TUNNEL_MULTICAST_DISABLE */
}


/*****************************************************************************/
/* Outer IPv6 multicast lookup                                               */
/*****************************************************************************/
#if !defined(IPV6_TUNNEL_MULTICAST_DISABLE)
table outer_ipv6_multicast_star_g {
    reads {
#ifdef OUTER_MULTICAST_BRIDGE_DISABLE
        l3_metadata.vrf : exact;
#else
        multicast_metadata.ipv6_mcast_key_type : exact;
        multicast_metadata.ipv6_mcast_key : exact;
#endif /* OUTER_MULTICAST_BRIDGE_DISABLE */
        ipv6.dstAddr : ternary;
    }
    actions {
        nop;
        outer_multicast_route_sm_star_g_hit;
        outer_multicast_route_bidir_star_g_hit;
#if !defined(OUTER_MULTICAST_BRIDGE_DISABLE)
        outer_multicast_bridge_star_g_hit;
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */
    }
    size : OUTER_MULTICAST_STAR_G_TABLE_SIZE;
}

table outer_ipv6_multicast {
    reads {
#ifdef OUTER_MULTICAST_BRIDGE_DISABLE
        l3_metadata.vrf : exact;
#else
        multicast_metadata.ipv6_mcast_key_type : exact;
        multicast_metadata.ipv6_mcast_key : exact;
#endif /* OUTER_MULTICAST_BRIDGE_DISABLE */
        ipv6.srcAddr : exact;
        ipv6.dstAddr : exact;
    }
    actions {
        nop;
        on_miss;
        outer_multicast_route_s_g_hit;
#if !defined(OUTER_MULTICAST_BRIDGE_DISABLE)
        outer_multicast_bridge_s_g_hit;
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */
    }
    size : OUTER_MULTICAST_S_G_TABLE_SIZE;
}
#endif /* !IPV6_TUNNEL_MULTICAST_DISABLE */

control process_outer_ipv6_multicast {
#if !defined(IPV6_TUNNEL_MULTICAST_DISABLE)
    /* check for ipv6 multicast tunnel termination  */
#ifdef OUTER_MULTICAST_BRIDGE_DISABLE
  if (multicast_metadata.ipv6_multicast_enabled==1) {
# else
    {
#endif /* OUTER_MULTICAST_BRIDGE_DISABLE */
      apply(outer_ipv6_multicast) {
        on_miss {
	  apply(outer_ipv6_multicast_star_g);
        }
      }
    }
#endif /* !IPV6_TUNNEL_MULTICAST_DISABLE */
}


/*****************************************************************************/
/* Process outer IP multicast                                                */
/*****************************************************************************/
control process_outer_multicast {
#if !defined(TUNNEL_MULTICAST_DISABLE)
    if (valid(ipv4)) {
        process_outer_ipv4_multicast();
#if !defined(IPV6_TUNNEL_MULTICAST_DISABLE)
    } else {
        if (valid(ipv6)) {
            process_outer_ipv6_multicast();
        }
#endif /* !IPV6_TUNNEL_MULTICAST_DISABLE */
    }
    process_outer_multicast_rpf();
#endif /* !TUNNEL_MULTICAST_DISABLE */
}


/*****************************************************************************/
/* IP multicast RPF check                                                    */
/*****************************************************************************/
#ifndef L3_MULTICAST_DISABLE
action multicast_rpf_check_pass() {
    modify_field(l3_metadata.routed, TRUE);
}

action multicast_rpf_check_fail() {
    modify_field(multicast_metadata.multicast_route_mc_index, 0);
    modify_field(multicast_metadata.mcast_route_hit, FALSE);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

table multicast_rpf {
    reads {
        multicast_metadata.mcast_rpf_group : exact;
        multicast_metadata.bd_mrpf_group : exact;
    }
    actions {
        multicast_rpf_check_pass;
        multicast_rpf_check_fail;
    }
    size : MCAST_RPF_TABLE_SIZE;
}
#endif /* L3_MULTICAST_DISABLE */

control process_multicast_rpf {
#if !defined(L3_MULTICAST_DISABLE) && !defined(PIM_BIDIR_OPTIMIZATION)
    if (multicast_metadata.mcast_route_hit == TRUE) {
        apply(multicast_rpf);
    }
#endif /* !L3_MULTICAST_DISABLE && !PIM_BIDIR_OPTIMIZATION */
}


/*****************************************************************************/
/* IP multicast lookup actions                                               */
/*****************************************************************************/
#ifndef MULTICAST_DISABLE
//#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
        // Note : Only L2 multicast case is handled for now
action multicast_bridge_hit(mc_index, copy_to_cpu) {
    modify_field(ingress_metadata.egress_ifindex, 0);
//    modify_field(ingress_metadata.egress_port_lag_index, 0);
    modify_field(ig_intr_md_for_tm.mcast_grp_b, mc_index);
    modify_field(multicast_metadata.mcast_bridge_hit, TRUE);
}

action multicast_bridge_miss() {
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
}

//#else
 action multicast_bridge_star_g_hit(mc_index, copy_to_cpu) {
    modify_field(multicast_metadata.multicast_bridge_mc_index, mc_index);
    modify_field(multicast_metadata.mcast_bridge_hit, TRUE);
    modify_field(multicast_metadata.mcast_copy_to_cpu, copy_to_cpu);
}

action multicast_bridge_s_g_hit(mc_index, copy_to_cpu) {
    modify_field(multicast_metadata.multicast_bridge_mc_index, mc_index);
    modify_field(multicast_metadata.mcast_bridge_hit, TRUE);
    modify_field(multicast_metadata.mcast_copy_to_cpu, copy_to_cpu);
}

action multicast_route_star_g_miss() {
  //    modify_field(l3_metadata.l3_copy, TRUE);
}

action multicast_route_sm_star_g_hit(mc_index, mcast_rpf_group, copy_to_cpu) {
    modify_field(multicast_metadata.mcast_mode, MCAST_MODE_SM);
    modify_field(multicast_metadata.multicast_route_mc_index, mc_index);
    modify_field(multicast_metadata.mcast_route_hit, TRUE);
    bit_xor(multicast_metadata.mcast_rpf_group, mcast_rpf_group,
            multicast_metadata.bd_mrpf_group);
    modify_field(multicast_metadata.mcast_copy_to_cpu, copy_to_cpu);
}

action multicast_route_bidir_star_g_hit(mc_index, mcast_rpf_group, copy_to_cpu) {
    modify_field(multicast_metadata.mcast_mode, MCAST_MODE_BIDIR);
    modify_field(multicast_metadata.multicast_route_mc_index, mc_index);
    modify_field(multicast_metadata.mcast_route_hit, TRUE);
#ifdef PIM_BIDIR_OPTIMIZATION
    bit_or(multicast_metadata.mcast_rpf_group, mcast_rpf_group,
           multicast_metadata.bd_mrpf_group);
#else
    modify_field(multicast_metadata.mcast_rpf_group, mcast_rpf_group);
#endif
    modify_field(multicast_metadata.mcast_copy_to_cpu, copy_to_cpu);
}

action multicast_route_s_g_hit(mc_index, mcast_rpf_group, copy_to_cpu) {
    modify_field(multicast_metadata.multicast_route_mc_index, mc_index);
    modify_field(multicast_metadata.mcast_mode, MCAST_MODE_SM);
    modify_field(multicast_metadata.mcast_route_hit, TRUE);
    modify_field(multicast_metadata.mcast_route_s_g_hit, TRUE);
    bit_xor(multicast_metadata.mcast_rpf_group, mcast_rpf_group,
            multicast_metadata.bd_mrpf_group);
    modify_field(multicast_metadata.mcast_copy_to_cpu, copy_to_cpu);
}

action multicast_redirect_to_cpu(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
}
//#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
#endif /* MULTICAST_DISABLE */


/*****************************************************************************/
/* IPv4 multicast lookup                                                     */
/*****************************************************************************/
#if !defined(IPV4_L2_MULTICAST_DISABLE)
table ipv4_multicast_bridge_star_g {
    reads {
        ingress_metadata.bd : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
    }
    actions {
        nop;
        multicast_bridge_star_g_hit;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        multicast_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
    }
    size : IPV4_MULTICAST_STAR_G_TABLE_SIZE;
}

table ipv4_multicast_bridge {
    reads {
#ifdef L2_MULTICAST_TERNARY_MATCH_ENABLE
        ingress_metadata.bd : ternary;
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
#ifdef CPU_TX_VLAN_MCAST_ENABLE
        ingress_metadata.bypass_lookups : ternary;
#endif
#else
        ingress_metadata.bd : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
#endif /* L2_MULTICAST_TERNARY_MATCH_ENABLE */
    }
    actions {
        on_miss;
#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
        multicast_bridge_hit;
        multicast_bridge_miss;
#else
        multicast_bridge_s_g_hit;
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
#ifdef SYSTEM_FLOW_ACL_ENABLE
        multicast_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
    }
    size : IPV4_MULTICAST_S_G_TABLE_SIZE;
}
#endif /* !IPV4_L2_MULTICAST_DISABLE */

#if !defined(IPV4_L3_MULTICAST_DISABLE)
counter ipv4_multicast_route_star_g_stats {
    type : packets;
    direct : ipv4_multicast_route_star_g;
}

counter ipv4_multicast_route_s_g_stats {
    type : packets;
    direct : ipv4_multicast_route;
}

table ipv4_multicast_route_star_g {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
    }
    actions {
        multicast_route_star_g_miss;
        multicast_route_sm_star_g_hit;
        multicast_route_bidir_star_g_hit;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        multicast_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
    }
    size : IPV4_MULTICAST_STAR_G_TABLE_SIZE;
}

table ipv4_multicast_route {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
    }
    actions {
        on_miss;
        multicast_route_s_g_hit;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        multicast_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
    }
    size : IPV4_MULTICAST_S_G_TABLE_SIZE;
}
#endif /* !IPV4_L3_MULTICAST_DISABLE */

control process_ipv4_multicast {
#if !defined(IPV4_L2_MULTICAST_DISABLE)
    /* ipv4 multicast lookup */
    if (DO_LOOKUP(L2)) {
#if !defined(L2_SG_MULTICAST_DISABLE)
        apply(ipv4_multicast_bridge) {
            on_miss {
                apply(ipv4_multicast_bridge_star_g);
            }
        }
#else
      apply(ipv4_multicast_bridge_star_g);
#endif /* L2_SG_MULTICAST_DISABLE */
    }
#endif /* !IPV4_L2_MULTICAST_DISABLE */

#if !defined(IPV4_L3_MULTICAST_DISABLE)
    if (DO_LOOKUP(L3) and
        (multicast_metadata.ipv4_multicast_enabled == TRUE)) {
        apply(ipv4_multicast_route) {
            on_miss {
                apply(ipv4_multicast_route_star_g);
            }
        }
    }
#endif /* !IPV4_L3_MULTICAST_DISABLE */
}


/*****************************************************************************/
/* IPv6 multicast lookup                                                     */
/*****************************************************************************/
#if !defined(IPV6_L2_MULTICAST_DISABLE)
table ipv6_multicast_bridge_star_g {
    reads {
        ingress_metadata.bd : exact;
        ipv6_metadata.lkp_ipv6_da : exact;
    }
    actions {
        nop;
        multicast_bridge_star_g_hit;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        multicast_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
    }
    size : IPV6_MULTICAST_STAR_G_TABLE_SIZE;
}

table ipv6_multicast_bridge {
    reads {
        ingress_metadata.bd : exact;
        ipv6_metadata.lkp_ipv6_sa : exact;
        ipv6_metadata.lkp_ipv6_da : exact;
    }
    actions {
        on_miss;
        multicast_bridge_s_g_hit;
#ifdef SYSTEM_FLOW_ACL_ENABLE
        multicast_redirect_to_cpu;
#endif /* SYSTEM_FLOW_ACL_ENABLE */
    }
    size : IPV6_MULTICAST_S_G_TABLE_SIZE;
}
#endif /* !IPV6_L2_MULTICAST_DISABLE */

#if !defined(IPV6_L3_MULTICAST_DISABLE)
counter ipv6_multicast_route_star_g_stats {
    type : packets;
    direct : ipv6_multicast_route_star_g;
}

counter ipv6_multicast_route_s_g_stats {
    type : packets;
    direct : ipv6_multicast_route;
}

table ipv6_multicast_route_star_g {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da : exact;
    }
    actions {
        multicast_route_star_g_miss;
        multicast_route_sm_star_g_hit;
        multicast_route_bidir_star_g_hit;
    }
    size : IPV6_MULTICAST_STAR_G_TABLE_SIZE;
}

table ipv6_multicast_route {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_sa : exact;
        ipv6_metadata.lkp_ipv6_da : exact;
    }
    actions {
        on_miss;
        multicast_route_s_g_hit;
    }
    size : IPV6_MULTICAST_S_G_TABLE_SIZE;
}
#endif /* !IPV6_L3_MULTICAST_DISABLE */

control process_ipv6_multicast {
#if !defined(IPV6_L2_MULTICAST_DISABLE)
    if (DO_LOOKUP(L2)) {
#if !defined(L2_SG_MULTICAST_DISABLE)
        apply(ipv6_multicast_bridge) {
            on_miss {
                apply(ipv6_multicast_bridge_star_g);
            }
        }
#else
    apply(ipv6_multicast_bridge_star_g);
#endif /* L2_SG_MULTICAST_DISABLE */
    }
#endif /* !IPV6_L2_MULTICAST_DISABLE */

#if !defined(IPV6_L3_MULTICAST_DISABLE)
    if (DO_LOOKUP(L3) and
        (multicast_metadata.ipv6_multicast_enabled == TRUE)) {
        apply(ipv6_multicast_route) {
            on_miss {
                apply(ipv6_multicast_route_star_g);
            }
        }
    }
#endif /* !IPV6_L3_MULTICAST_DISABLE */
}


/*****************************************************************************/
/* IP multicast processing                                                   */
/*****************************************************************************/
control process_multicast {
#if !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE)
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
        process_ipv4_multicast();
    } else {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
            process_ipv6_multicast();
        }
    }
    process_multicast_rpf();
#endif /* !L2_MULTICAST_DISABLE || !L3_MULTICAST_DISABLE */
}


/*****************************************************************************/
/* Multicast flooding                                                        */
/*****************************************************************************/
action set_bd_flood_mc_index(mc_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_b, mc_index);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, INVALID_PORT_ID);
}

table bd_flood {
    reads {
        ingress_metadata.bd : exact;
        l2_metadata.lkp_pkt_type : exact;
#if !defined(L3_MULTICAST_DISABLE)
        multicast_metadata.flood_to_mrouters : exact;
#endif /* !L3_MULTICAST_DISABLE */
    }
    actions {
        nop;
        set_bd_flood_mc_index;
    }
    size : BD_FLOOD_TABLE_SIZE;
}

control process_multicast_flooding {
#ifndef MULTICAST_DISABLE
    apply(bd_flood);
#endif /* MULTICAST_DISABLE */
}


/*****************************************************************************/
/* Multicast replication processing                                          */
/*****************************************************************************/
#if defined(TUNNEL_NEXTHOP_ENABLE) || !defined(MULTICAST_DISABLE) || \
    defined(DTEL_REPORT_ENABLE)
#if !defined(TUNNEL_MULTICAST_DISABLE)
action outer_replica_from_rid(bd, dmac_idx, tunnel_index, tunnel_type, header_count) {
  // Encap -> Encap copy
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.outer_bd, bd);
    modify_field(multicast_metadata.replica, TRUE);
    modify_field(multicast_metadata.inner_replica, FALSE);
    modify_field(egress_metadata.routed, l3_metadata.outer_routed);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.outer_bd);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, tunnel_type);
    modify_field(tunnel_metadata.egress_header_count, header_count);
    modify_field(tunnel_metadata.tunnel_dmac_index, dmac_idx);
}

action encap_replica_from_rid(bd, dmac_idx, tunnel_index, tunnel_type, header_count, outer_bd) {
   // Native -> encap OR Re-encap case
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.outer_bd, outer_bd);
    modify_field(multicast_metadata.replica, TRUE);
    modify_field(multicast_metadata.inner_replica, TRUE);
    modify_field(egress_metadata.routed, l3_metadata.routed);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.bd);
    // TODO : in the re-encap case, we also need to do same_bd_check for outer_bd
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_tunnel_type, tunnel_type);
    modify_field(tunnel_metadata.egress_header_count, header_count);
    modify_field(tunnel_metadata.tunnel_dmac_index, dmac_idx);
}
#endif /* !TUNNEL_MULTICAST_DISABLE */

action inner_replica_from_rid(bd) {
  // Native -> Native OR Encap -> Native
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.outer_bd, bd);
    modify_field(multicast_metadata.replica, TRUE);
#if !defined(TUNNEL_MULTICAST_DISABLE)
    modify_field(multicast_metadata.inner_replica, TRUE);
#endif /* !TUNNEL_MULTICAST_DISABLE */
    modify_field(egress_metadata.routed, l3_metadata.routed);
    bit_xor(egress_metadata.same_bd_check, bd, ingress_metadata.bd);
}

action unicast_replica_from_rid(outer_bd, dmac_idx) {
    modify_field(egress_metadata.outer_bd, outer_bd);
    modify_field(tunnel_metadata.tunnel_dmac_index, dmac_idx);
}

@pragma ignore_table_dependency mirror
#ifndef ENT_V6_DTEL_PROFILE        
#ifdef DTEL_QUEUE_REPORT_ENABLE
@pragma stage 0
@pragma ways 4
#endif
#endif
table rid {
    reads {
        eg_intr_md.egress_rid : exact;
    }
    actions {
        nop;
#if !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE)
#if !defined(TUNNEL_MULTICAST_DISABLE)
        outer_replica_from_rid;
	    encap_replica_from_rid;
#endif /* !TUNNEL_MULTICAST_DISABLE */
        inner_replica_from_rid;
#endif /* !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE) */
#if defined (TUNNEL_NEXTHOP_ENABLE) || defined(DTEL_REPORT_ENABLE)
        unicast_replica_from_rid;
#endif /* TUNNEL_NEXTHOP_ENABLE || DTEL_REPORT_ENABLE */
    }
    size : RID_TABLE_SIZE;
}

//#if !defined(L3_MULTICAST_DISABLE)
action set_replica_copy_bridged() {
    modify_field(egress_metadata.routed, FALSE);
}

#if defined(ENT_FIN_POSTCARD_PROFILE)
@pragma stage 1
#endif
table replica_type {
    reads {
        multicast_metadata.replica : exact;
        egress_metadata.same_bd_check : ternary;
    }
    actions {
        nop;
        set_replica_copy_bridged;
    }
    size : REPLICA_TYPE_TABLE_SIZE;
}
#endif
//#endif /* L3_MULTICAST_DISABLE */

/* We have to split replication processing into two control
blocks because we want rid and mirror table to be in
stage 0. But, the compiler does not do this when
rid, mcast_egress_rid and replica_type tables are
under the same gateway condition. process_rid should
be invoked before process_mirroring, and
process_replication should be invoked after */

control process_rid {
#if defined(TUNNEL_NEXTHOP_ENABLE) || !defined(MULTICAST_DISABLE) || \
    defined(DTEL_REPORT_ENABLE)
    if(eg_intr_md.egress_rid != 0) {
        /* set info from rid */
        apply(rid);
    }
#endif /* TUNNEL_NEXTHOP_ENABLE || MULTICAST_DISABLE || DTEL_REPORT_ENABLE */
}

control process_replication {
#if !defined(L3_MULTICAST_DISABLE)
    if(eg_intr_md.egress_rid != 0) {
        /*  routed or bridge replica */
        apply(replica_type);
    }
#endif /* L3_MULTICAST_DISABLE */
}

/*
 * PIM BIDIR DF check optimization description
 Assumption : Number of RPs in the network is X
 PIM_DF_CHECK_BITS : X

 For each RP, there is list of interfaces for which the switch is
 the designated forwarder.

 For example:
 RP1 : BD1, BD2, BD5
 RP2 : BD3, BD5
 ...
 RP16 : BD1, BD5

 RP1  is allocated value 0x0001
 RP2  is allocated value 0x0002
 ...
 RP16 is allocated value 0x8000

 With each BD, we store a bitmap of size PIM_DF_CHECK_BITS with all
 RPx that it belongs to set.

 BD1 : 0x8001 (1000 0000 0000 0001)
 BD2 : 0x0001 (0000 0000 0000 0001)
 BD3 : 0x0002 (0000 0000 0000 0010)
 BD5 : 0x8003 (1000 0000 0000 0011)

 With each (*,G) entry, we store the RP value.

 DF check : <RP value from (*,G) entry> & <mrpf group value from bd>
 If 0, rpf check fails.

 Eg, If (*,G) entry uses RP2, and packet comes in BD3 or BD5, then RPF
 check passes. If packet comes in any other interface, logical and
 operation will yield 0.
 */
