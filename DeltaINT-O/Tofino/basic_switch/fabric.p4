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
 * Fabric processing for multi-device system
 */


header_type fabric_metadata_t {
    fields {
        packetType : 3;
        fabric_header_present : 1;
        reason_code : 16;              /* cpu reason code */

#ifdef FABRIC_ENABLE
        dst_device : 8;                /* destination device id */
        dst_port : 16;                 /* destination port id */
#endif /* FABRIC_ENABLE */
    }
}

#if defined(FABRIC_PROFILE)
/* This field is part of bridged metadata.  The fabric
   profile puts a lot of pressure on 16-bit containers.
   Even though the natural container size of this field is 16,
   it can safely be allocated in a 32-bit container since its
   MAU cluster size is 1. */
@pragma pa_container_size ingress fabric_metadata.reason_code 32
#endif
@pragma pa_solitary ingress fabric_metadata.reason_code
metadata fabric_metadata_t fabric_metadata;

/*****************************************************************************/
/* Fabric header - destination lookup                                        */
/*****************************************************************************/
#ifdef CPU_TX_TC_QUEUE_ENABLE
action terminate_cpu_packet(qid) {
#else 
action terminate_cpu_packet() {
#endif /* CPU_TX_TC_QUEUE_ENABLE */
#ifdef FABRIC_HEADER_OPTIMIZATION_ENABLE
    modify_field(ig_intr_md_for_tm.ucast_egress_port,
                 fabric_header_cpu.dstPortOrGroup);
#else
    modify_field(ig_intr_md_for_tm.ucast_egress_port,
                 fabric_header.dstPortOrGroup);
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
    modify_field(egress_metadata.bypass, fabric_header_cpu.txBypass);

#ifdef CPU_TX_TC_QUEUE_ENABLE
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(qos_metadata.lkp_tc, fabric_header.egressTc);
#endif /* CPU_TX_TC_QUEUE_ENABLE */
#ifdef PTP_ENABLE
    modify_field(egress_metadata.capture_tstamp_on_tx, fabric_header_cpu.capture_tstamp_on_tx);
#endif /* PTP_ENABLE */

    modify_field(ethernet.etherType, fabric_payload_header.etherType);
#ifndef FABRIC_HEADER_OPTIMIZATION_ENABLE
    remove_header(fabric_header);
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
    remove_header(fabric_header_cpu);
    remove_header(fabric_payload_header);
}

#ifdef CPU_TX_VLAN_MCAST_ENABLE
#ifdef CPU_TX_TC_QUEUE_ENABLE
action terminate_cpu_multicast_packet(qid) {
#else
action terminate_cpu_multicast_packet() {
#endif
#ifdef FABRIC_HEADER_OPTIMIZATION_ENABLE
    modify_field(ig_intr_md_for_tm.mcast_grp_b, 
                 fabric_header_cpu.dstPortOrGroup);
#else
    modify_field(ig_intr_md_for_tm.mcast_grp_b, 
                 fabric_header.dstPortOrGroup);
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
    modify_field(ig_intr_md_for_tm.ucast_egress_port, INVALID_PORT_ID);
    modify_field(ingress_metadata.egress_ifindex, 0);
    modify_field(egress_metadata.bypass, fabric_header_cpu.txBypass);
#ifdef CPU_TX_TC_QUEUE_ENABLE
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(qos_metadata.lkp_tc, fabric_header.egressTc);
#endif /* CPU_TX_TC_QUEUE_ENABLE */
#ifdef PTP_ENABLE
    modify_field(egress_metadata.capture_tstamp_on_tx, fabric_header_cpu.capture_tstamp_on_tx);
#endif /* PTP_ENABLE */

    modify_field(ethernet.etherType, fabric_payload_header.etherType);
#ifndef FABRIC_HEADER_OPTIMIZATION_ENABLE
    remove_header(fabric_header);
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
    remove_header(fabric_header_cpu);
    remove_header(fabric_payload_header);
}
#endif /* CPU_TX_VLAN_MCAST_ENABLE */

#ifdef FABRIC_ENABLE
action terminate_fabric_unicast_packet() {
    modify_field(ig_intr_md_for_tm.ucast_egress_port,
                 fabric_header.dstPortOrGroup);

    modify_field(tunnel_metadata.tunnel_terminate,
                 fabric_header_unicast.tunnelTerminate);
    modify_field(tunnel_metadata.ingress_tunnel_type,
                 fabric_header_unicast.ingressTunnelType);
    modify_field(l3_metadata.nexthop_index,
                 fabric_header_unicast.nexthopIndex);
    modify_field(l3_metadata.routed, fabric_header_unicast.routed);
    modify_field(l3_metadata.outer_routed,
                 fabric_header_unicast.outerRouted);

    modify_field(ethernet.etherType, fabric_payload_header.etherType);
    remove_header(fabric_header);
    remove_header(fabric_header_unicast);
    remove_header(fabric_payload_header);
}

action switch_fabric_unicast_packet() {
    modify_field(fabric_metadata.fabric_header_present, TRUE);
    modify_field(fabric_metadata.dst_device, fabric_header.dstDevice);
    modify_field(fabric_metadata.dst_port, fabric_header.dstPortOrGroup);
}

#ifndef MULTICAST_DISABLE
action terminate_fabric_multicast_packet() {
    modify_field(tunnel_metadata.tunnel_terminate,
                 fabric_header_multicast.tunnelTerminate);
    modify_field(tunnel_metadata.ingress_tunnel_type,
                 fabric_header_multicast.ingressTunnelType);
    modify_field(l3_metadata.nexthop_index, 0);
    modify_field(l3_metadata.routed, fabric_header_multicast.routed);
    modify_field(l3_metadata.outer_routed,
                 fabric_header_multicast.outerRouted);

    modify_field(ig_intr_md_for_tm.mcast_grp_a,
                 fabric_header_multicast.mcastGrpA);
    modify_field(ig_intr_md_for_tm.mcast_grp_b, fabric_header_multicast.mcastGrpB);
    modify_field(ig_intr_md_for_tm.rid, fabric_header_multicast.ingressRid);
    modify_field(ig_intr_md_for_tm.level1_exclusion_id,
                 fabric_header_multicast.l1ExclusionId);

    modify_field(ethernet.etherType, fabric_payload_header.etherType);
    remove_header(fabric_header);
    remove_header(fabric_header_multicast);
    remove_header(fabric_payload_header);
}

action switch_fabric_multicast_packet() {
    modify_field(fabric_metadata.fabric_header_present, TRUE);
    modify_field(ig_intr_md_for_tm.mcast_grp_a, 0);
    modify_field(ig_intr_md_for_tm.mcast_grp_b, fabric_header.dstPortOrGroup);
    modify_field(ig_intr_md_for_tm.rid, 0);
    modify_field(ig_intr_md_for_tm.level1_exclusion_id, 0);
}
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */

@pragma ternary 1
table fabric_ingress_dst_lkp {
#ifndef FABRIC_HEADER_OPTIMIZATION_ENABLE
    reads {
        fabric_header.dstDevice : exact;
#ifdef CPU_TX_TC_QUEUE_ENABLE
        fabric_header_cpu.egressQueue : exact;
#endif
    }
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
    actions {
#ifndef FABRIC_HEADER_OPTIMIZATION_ENABLE
        nop;
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
        terminate_cpu_packet;
#ifdef FABRIC_ENABLE
        switch_fabric_unicast_packet;
        terminate_fabric_unicast_packet;
#ifndef MULTICAST_DISABLE
        switch_fabric_multicast_packet;
        terminate_fabric_multicast_packet;
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
    }
}

/*****************************************************************************/
/* Fabric header - source lookup                                             */
/*****************************************************************************/
#ifdef FABRIC_ENABLE
action set_ingress_ifindex_properties(l2xid) {
    modify_field(ig_intr_md_for_tm.level2_exclusion_id, l2xid);
}

table fabric_ingress_src_lkp {
    reads {
        fabric_header_multicast.ingressIfindex : exact;
    }
    actions {
        nop;
        set_ingress_ifindex_properties;
    }
    size : 1024;
}
#endif /* FABRIC_ENABLE */

action non_ip_over_fabric() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action ipv4_over_fabric() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(ipv4_metadata.lkp_ipv4_sa, ipv4.srcAddr);
    modify_field(ipv4_metadata.lkp_ipv4_da, ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv4.protocol);
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_outer_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_outer_l4_dport);
}

action ipv6_over_fabric() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(ipv6_metadata.lkp_ipv6_sa, ipv6.srcAddr);
    modify_field(ipv6_metadata.lkp_ipv6_da, ipv6.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv6.nextHdr);
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_outer_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_outer_l4_dport);
}

table native_packet_over_fabric {
    reads {
        ipv4 : valid;
        ipv6 : valid;
    }
    actions {
        non_ip_over_fabric;
        ipv4_over_fabric;
#ifndef IPV6_DISABLE
        ipv6_over_fabric;
#endif /* IPV6_DISABLE */
    }
    size : 1024;
}

action rewrite_l2_exclusion_id(exclusion_id, rid) {
    modify_field(ig_intr_md_for_tm.level2_exclusion_id, exclusion_id);
    modify_field(ig_intr_md_for_tm.rid, rid);
}

table l2_exclusion_id_rewrite {
    reads {
        fabric_header_cpu.ingressPort : exact;
    }
    actions {
      rewrite_l2_exclusion_id;
    }
    size : 512;
}

#ifdef CPU_TX_VLAN_MCAST_ENABLE
table fabric_mcast_packet {
    reads {
        fabric_header.mcast : exact;
#ifdef CPU_TX_TC_QUEUE_ENABLE
        fabric_header_cpu.egressQueue : exact;
#endif
    }
    actions {
      terminate_cpu_multicast_packet;
    }
    size : 512;
}
#endif

control process_cpu_packet {
#ifdef CPU_TX_YID_REWRITE_ENABLE
    /* YID rewrite for CPU-TX packets */
    if (ingress_metadata.port_type == PORT_TYPE_CPU) {
        apply(l2_exclusion_id_rewrite);
    }
#endif /* CPU_TX_YID_REWRITE_ENABLE */
}
    
/*****************************************************************************/
/* Ingress fabric header processing                                          */
/*****************************************************************************/
control process_ingress_fabric {
#ifdef Q0_PROFILE
    if(ingress_metadata.port_type == PORT_TYPE_CPU) {
#else
    if ((ingress_metadata.port_type != PORT_TYPE_NORMAL)) {
#endif
        apply(fabric_ingress_dst_lkp);
#ifdef FABRIC_ENABLE
        if (ingress_metadata.port_type == PORT_TYPE_FABRIC) {
            if (valid(fabric_header_multicast)) {
                apply(fabric_ingress_src_lkp);
            }
            if (tunnel_metadata.tunnel_terminate == FALSE) {
                apply(native_packet_over_fabric);
            }
        }
#endif /* FABRIC_ENABLE */
    }
}

/*****************************************************************************/
/* Fabric LAG resolution                                                     */
/*****************************************************************************/
#ifdef FABRIC_ENABLE
action set_fabric_lag_port(port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}

#ifndef MULTICAST_DISABLE
action set_fabric_multicast(fabric_mgid) {
    modify_field(multicast_metadata.mcast_grp_a, ig_intr_md_for_tm.mcast_grp_a);
    modify_field(multicast_metadata.mcast_grp_b, ig_intr_md_for_tm.mcast_grp_b);
    modify_field(multicast_metadata.ingress_rid, ig_intr_md_for_tm.rid);
    modify_field(multicast_metadata.l1_exclusion_id,
                 ig_intr_md_for_tm.level1_exclusion_id);

#ifdef FABRIC_NO_LOCAL_SWITCHING
    // no local switching, reset fields to send packet on fabric mgid
    modify_field(ig_intr_md_for_tm.mcast_grp_a, fabric_mgid);
    modify_field(ig_intr_md_for_tm.mcast_grp_b, 0);
    modify_field(ig_intr_md_for_tm.rid, 0);
    modify_field(ig_intr_md_for_tm.level1_exclusion_id, 0);
    modify_field(ig_intr_md_for_tm.level2_exclusion_id, 0);
#endif /* FABRIC_NO_LOCAL_SWITCHING */
}
#endif /* MULTICAST_DISABLE */

field_list fabric_lag_hash_fields {
    hash_metadata.hash2;
}

field_list_calculation fabric_lag_hash {
    input {
        fabric_lag_hash_fields;
    }
    algorithm : identity;
    output_width : 14; //LAG_BIT_WIDTH;
}

action_selector fabric_lag_selector {
    selection_key : fabric_lag_hash;
    selection_mode : fair;
}

action_profile fabric_lag_action_profile {
    actions {
        nop;
        set_fabric_lag_port;
#ifndef MULTICAST_DISABLE
        set_fabric_multicast;
#endif /* MULTICAST_DISABLE */
    }
    size : LAG_GROUP_TABLE_SIZE;
    dynamic_action_selection : fabric_lag_selector;
}

table fabric_lag {
    reads {
        fabric_metadata.dst_device : exact;
    }
    action_profile: fabric_lag_action_profile;
}
#endif /* FABRIC_ENABLE */

control process_fabric_lag {
#ifdef FABRIC_ENABLE
    apply(fabric_lag);
#endif /* FABRIC_ENABLE */
}


/*****************************************************************************/
/* Fabric rewrite actions                                                    */
/*****************************************************************************/
action cpu_rx_rewrite() {
#ifdef FABRIC_HEADER_OPTIMIZATION_ENABLE
    add_header(fabric_header_cpu);
    modify_field(fabric_header_cpu.ingressPort, ingress_metadata.ingress_port);
    modify_field(fabric_header_cpu.ingressIfindex, ingress_metadata.ifindex);
    modify_field(fabric_header_cpu.ingressBd, ingress_metadata.bd);
    modify_field(fabric_header_cpu.reasonCode, fabric_metadata.reason_code);
#ifdef INT_TRANSIT_ENABLE
    modify_field(fabric_header_cpu.dtelIntPresent, int_header.valid);
#elif defined(INT_EP_ENABLE)
    modify_field(fabric_header_cpu.dtelIntPresent, 0);
#endif

#else /* FABRIC_HEADER_OPTIMIZATION_ENABLE */

    add_header(fabric_header);
    modify_field(fabric_header.headerVersion, 0);
    modify_field(fabric_header.packetVersion, 0);
    modify_field(fabric_header.mcast, 0);
    modify_field(fabric_header.packetType, FABRIC_HEADER_TYPE_CPU);
    add_header(fabric_header_cpu);
    modify_field(fabric_header_cpu.ingressPort, ingress_metadata.ingress_port);
    modify_field(fabric_header_cpu.ingressIfindex, ingress_metadata.ifindex);
    modify_field(fabric_header_cpu.ingressBd, ingress_metadata.bd);
    modify_field(fabric_header_cpu.reasonCode, fabric_metadata.reason_code);
#ifdef INT_TRANSIT_ENABLE
    modify_field(fabric_header_cpu.dtelIntPresent, int_header.valid);
#elif defined(INT_EP_ENABLE)
    modify_field(fabric_header_cpu.dtelIntPresent, 0);
#endif

#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */
    add_header(fabric_payload_header);
    modify_field(fabric_payload_header.etherType, ethernet.etherType);
    modify_field(ethernet.etherType, ETHERTYPE_BF_FABRIC);
}

action fabric_rewrite(tunnel_index) {
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
}

#ifdef FABRIC_ENABLE
action fabric_unicast_rewrite() {
    add_header(fabric_header);
    modify_field(fabric_header.headerVersion, 0);
    modify_field(fabric_header.packetVersion, 0);
    modify_field(fabric_header.mcast, 0);
    modify_field(fabric_header.packetType, FABRIC_HEADER_TYPE_UNICAST);
    modify_field(fabric_header.dstDevice, fabric_metadata.dst_device);
    modify_field(fabric_header.dstPortOrGroup, fabric_metadata.dst_port);

    add_header(fabric_header_unicast);
    modify_field(fabric_header_unicast.tunnelTerminate,
                 tunnel_metadata.tunnel_terminate);
    modify_field(fabric_header_unicast.routed, l3_metadata.routed);
    modify_field(fabric_header_unicast.outerRouted,
                 l3_metadata.outer_routed);
    modify_field(fabric_header_unicast.ingressTunnelType,
                 tunnel_metadata.ingress_tunnel_type);
    modify_field(fabric_header_unicast.nexthopIndex,
                 l3_metadata.nexthop_index);
    add_header(fabric_payload_header);
    modify_field(fabric_payload_header.etherType, ethernet.etherType);
    modify_field(ethernet.etherType, ETHERTYPE_BF_FABRIC);
}

#ifndef MULTICAST_DISABLE
action fabric_multicast_rewrite(fabric_mgid) {
    add_header(fabric_header);
    modify_field(fabric_header.headerVersion, 0);
    modify_field(fabric_header.packetVersion, 0);
    modify_field(fabric_header.mcast, 0);
    modify_field(fabric_header.packetType, FABRIC_HEADER_TYPE_MULTICAST);
    modify_field(fabric_header.dstDevice, FABRIC_DEVICE_MULTICAST);
    modify_field(fabric_header.dstPortOrGroup, fabric_mgid);
    modify_field(fabric_header_multicast.ingressIfindex, ingress_metadata.ifindex);
    modify_field(fabric_header_multicast.ingressBd, ingress_metadata.bd);

    add_header(fabric_header_multicast);
    modify_field(fabric_header_multicast.tunnelTerminate,
                 tunnel_metadata.tunnel_terminate);
    modify_field(fabric_header_multicast.routed, l3_metadata.routed);
    modify_field(fabric_header_multicast.outerRouted,
                 l3_metadata.outer_routed);
    modify_field(fabric_header_multicast.ingressTunnelType,
                 tunnel_metadata.ingress_tunnel_type);

    modify_field(fabric_header_multicast.mcastGrpA,
                 multicast_metadata.mcast_grp_a);
    modify_field(fabric_header_multicast.mcastGrpB,
                 multicast_metadata.mcast_grp_b);
    modify_field(fabric_header_multicast.ingressRid,
                 multicast_metadata.ingress_rid);
    modify_field(fabric_header_multicast.l1ExclusionId,
                 multicast_metadata.l1_exclusion_id);

    add_header(fabric_payload_header);
    modify_field(fabric_payload_header.etherType, ethernet.etherType);
    modify_field(ethernet.etherType, ETHERTYPE_BF_FABRIC);
}
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
