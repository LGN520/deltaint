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
 * Input processing - port and packet related
 */

/*****************************************************************************/
/* Validate outer packet header                                              */
/*****************************************************************************/
action set_valid_outer_unicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}

action set_valid_outer_unicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}

#ifndef DOUBLE_TAGGED_DISABLE
action set_valid_outer_unicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}
#endif /* !DOUBLE_TAGGED_DISABLE */

action set_valid_outer_unicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}

action set_valid_outer_multicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}

action set_valid_outer_multicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}

#ifndef DOUBLE_TAGGED_DISABLE
action set_valid_outer_multicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}
#endif /* !DOUBLE_TAGGED_DISABLE */

action set_valid_outer_multicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
#ifdef CPU_TX_VLAN_MCAST_ENABLE
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
#endif /* CPU_TX_VLAN_MCAST_ENABLE */
}

action set_valid_outer_broadcast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
}

action set_valid_outer_broadcast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
}

#ifndef DOUBLE_TAGGED_DISABLE
action set_valid_outer_broadcast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
}
#endif /* !DOUBLE_TAGGED_DISABLE */

action set_valid_outer_broadcast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
    modify_field(l2_metadata.lkp_cfi, vlan_tag_[0].cfi);
#endif
    modify_field(ingress_metadata.egress_ifindex, 0x3FFF);
}

action malformed_outer_ethernet_packet(drop_reason) {
#ifdef ALT_INGRESS_DROP_ENABLE
#else
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, drop_reason);
#endif /* ALT_INGRESS_DROP_ENABLE */
}

table validate_outer_ethernet {
    reads {
        ethernet.srcAddr : ternary;
        ethernet.dstAddr : ternary;
        vlan_tag_[0].valid : ternary;
#if !defined(DOUBLE_TAGGED_DISABLE) || defined(QINQ_ENABLE)
        vlan_tag_[1].valid : ternary;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }
    actions {
        malformed_outer_ethernet_packet;
        set_valid_outer_unicast_packet_untagged;
        set_valid_outer_unicast_packet_single_tagged;
#ifndef DOUBLE_TAGGED_DISABLE
        set_valid_outer_unicast_packet_double_tagged;
        set_valid_outer_multicast_packet_double_tagged;
        set_valid_outer_broadcast_packet_double_tagged;
#endif /* !DOUBLE_TAGGED_DISABLE */
        set_valid_outer_unicast_packet_qinq_tagged;
        set_valid_outer_multicast_packet_untagged;
        set_valid_outer_multicast_packet_single_tagged;
        set_valid_outer_multicast_packet_qinq_tagged;
        set_valid_outer_broadcast_packet_untagged;
        set_valid_outer_broadcast_packet_single_tagged;
        set_valid_outer_broadcast_packet_qinq_tagged;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control process_validate_outer_header {
    /* validate the ethernet header */
    apply(validate_outer_ethernet) {
        malformed_outer_ethernet_packet {
        }
        default {
            #ifdef ALT_IP_PKT_VALIDATE_ENABLE
            if (valid(ipv4) or valid(ipv6)) {
                validate_outer_ip_header();
            }
            #else
            if (valid(ipv4)) {
                validate_outer_ipv4_header();
            } else {
                if (valid(ipv6)) {
                    validate_outer_ipv6_header();
                }
            }
            #endif /* ALT_IP_PKT_VALIDATE_ENABLE */
#ifndef MPLS_DISABLE
            if (valid(mpls[0])) {
                validate_mpls_header();
            }
#endif
        }
    }
}


/*****************************************************************************/
/* Ingress port lookup                                                       */
/*****************************************************************************/

action set_port_lag_index(port_lag_index, port_type, neighbor_id) {
    modify_field(ingress_metadata.port_lag_index, port_lag_index);
    modify_field(ingress_metadata.port_type, port_type);
#ifdef TRANSIENT_LOOP_PREVENTION
    modify_field(nexthop_metadata.nexthop_offset, neighbor_id);
#endif
}

table ingress_port_mapping {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_port_lag_index;
    }
    default_action: set_port_lag_index;
    size : PORTMAP_TABLE_SIZE;
}

field_list ingress_tstamp_hi_hash_fields {
    ig_intr_md.ingress_mac_tstamp;
}

field_list_calculation ingress_tstamp_hi_hash_fields_calc {
    input { ingress_tstamp_hi_hash_fields; }
    algorithm : identity_msb;
    output_width : 16;
}


action set_ingress_port_properties(port_lag_label, exclusion_id,
                                   qos_group, tc_qos_group,
                                   tc, color,
                                   learning_enabled,
                                   trust_dscp, trust_pcp,
                                   mac_pkt_classify) {
    modify_field(ig_intr_md_for_tm.level2_exclusion_id, exclusion_id);
    modify_field(acl_metadata.port_lag_label, port_lag_label);
    modify_field(qos_metadata.ingress_qos_group, qos_group);
#ifndef GLOBAL_TC_ICOS_QUEUE_TABLE
    modify_field(qos_metadata.tc_qos_group, tc_qos_group);
#endif
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(ig_intr_md_for_tm.packet_color, color);
    modify_field(qos_metadata.trust_dscp, trust_dscp);
    modify_field(qos_metadata.trust_pcp, trust_pcp);
    modify_field(l2_metadata.port_learning_enabled, learning_enabled);
#ifdef PTP_ENABLE
    modify_field_with_hash_based_offset(i2e_metadata.ingress_tstamp_hi, 0,
                                        ingress_tstamp_hi_hash_fields_calc, 65536);
#endif /* PTP_ENABLE */
#ifdef SWITCH_CONFIG_DISABLE
#ifndef TIMESTAMP_DISABLE
    modify_field(i2e_metadata.ingress_tstamp, ig_intr_md.ingress_mac_tstamp);
#endif
    modify_field(ingress_metadata.ingress_port, ig_intr_md.ingress_port);
#endif
#ifdef MAC_PKT_CLASSIFY_ENABLE
    modify_field(acl_metadata.mac_pkt_classify, mac_pkt_classify);
#endif
}

#ifdef MSDC_L3_PROFILE
@pragma ternary 1
#endif
table ingress_port_properties {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_ingress_port_properties;
    }
    size : PORT_TABLE_SIZE;
}

control process_ingress_port_mapping {
    if (ig_intr_md.resubmit_flag == 0) {
        apply(ingress_port_mapping);
    }
    apply(ingress_port_properties);
}

/*****************************************************************************/
/* Ingress port-vlan mapping lookups                                         */
/*****************************************************************************/

//-------------------------
// BD Properties
//-------------------------
action set_bd_properties(bd, vrf, stp_group, learning_enabled,
                         bd_label, stats_idx, rmac_group,
                         ipv4_unicast_enabled, ipv6_unicast_enabled,
                         ipv4_urpf_mode, ipv6_urpf_mode,
                         igmp_snooping_enabled, mld_snooping_enabled,
                         ipv4_multicast_enabled, ipv6_multicast_enabled,
                         mrpf_group,
                         ipv4_mcast_key, ipv4_mcast_key_type,
                         ipv6_mcast_key, ipv6_mcast_key_type,
                         ingress_rid) {
    modify_field(ingress_metadata.bd, bd);
#ifndef TUNNEL_MULTICAST_DISABLE
    modify_field(ingress_metadata.outer_bd, bd);
#endif /* TUNNEL_MULTICAST_DISABLE */
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.stp_group, stp_group);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);
    modify_field(l2_metadata.learning_enabled, learning_enabled);

    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
#ifndef IPV6_DISABLE
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
    modify_field(multicast_metadata.ipv6_multicast_enabled,
                 ipv6_multicast_enabled);
    modify_field(multicast_metadata.mld_snooping_enabled, mld_snooping_enabled);
#endif /* IPV6_DISABLE */
#ifndef URPF_DISABLE
    modify_field(ipv4_metadata.ipv4_urpf_mode, ipv4_urpf_mode);
    modify_field(ipv6_metadata.ipv6_urpf_mode, ipv6_urpf_mode);
#endif /* !URPF_DISABLE */
    modify_field(l3_metadata.rmac_group, rmac_group);

    modify_field(multicast_metadata.igmp_snooping_enabled,
                 igmp_snooping_enabled);
    modify_field(multicast_metadata.ipv4_multicast_enabled,
                 ipv4_multicast_enabled);
    modify_field(multicast_metadata.bd_mrpf_group, mrpf_group);
#ifndef OUTER_MULTICAST_BRIDGE_DISABLE
    modify_field(multicast_metadata.ipv4_mcast_key_type, ipv4_mcast_key_type);
    modify_field(multicast_metadata.ipv4_mcast_key, ipv4_mcast_key);
    modify_field(multicast_metadata.ipv6_mcast_key_type, ipv6_mcast_key_type);
    modify_field(multicast_metadata.ipv6_mcast_key, ipv6_mcast_key);
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */
    modify_field(ig_intr_md_for_tm.rid, ingress_rid);
}

action port_vlan_mapping_miss() {
    modify_field(l2_metadata.port_vlan_mapping_miss, TRUE);
}

action local_sid_miss() {
}

action_profile bd_action_profile {
    actions {
        set_bd_properties;
        port_vlan_mapping_miss;
        local_sid_miss;
    }
    size : BD_TABLE_SIZE;
}

//---------------------------------------------------------
// {port, vlan} -> BD mapping
// For Access ports, L3 interfaces and L2 sub-ports
//---------------------------------------------------------

@pragma ignore_table_dependency my_sid
table port_vlan_to_bd_mapping {
    reads {
        ingress_metadata.port_lag_index : ternary;
        vlan_tag_[0] : valid;
        vlan_tag_[0].vid : ternary;
        // {port_lag_idx, 0, *}    entry for every L3 interface
        // {port_lag_idx, 1, vlan} entry for every L3 sub-interface
        // {port_lag_idx, 0, *}    entry for every access port/lag + untagged packet
        // {port_lag_idx, 1, vlan} entry for every access port/lag + packets tagged with access_vlan
        // {port_lag_idx, 1, 0}    entry for every access port/lag + .1p tagged packets
        // {port_lag_idx, 1, vlan} entry for every l2 sub-port (if supported)
        // {port_lag_idx, 0, *}    entry for every trunk port/lag if native-vlan is not tagged
        // {port_lag_index, *, *} -> port_vlan_mapping_miss action. Low priority catch-all entry - one for every non-trunk port.
    }
    action_profile: bd_action_profile;
#ifdef __p4c__
    const default_action: nop();
#endif
    size : PORT_VLAN_TABLE_SIZE;
}

//--------------------------------------------------------
// vlan->BD mapping for trunk ports
//--------------------------------------------------------
#ifndef __p4c__
@pragma ignore_table_dependency port_qinq_to_bd_mapping
@pragma ignore_table_dependency port_vlan_to_bd_mapping
#endif
table vlan_to_bd_mapping {
    reads {
        vlan_tag_[0].vid : exact;
        // one entry for every vlan
    }
    action_profile: bd_action_profile;
#ifdef __p4c__
    const default_action: nop();
#endif
    size : VLAN_TABLE_SIZE;
}

#ifdef QINQ_RIF_ENABLE            
//--------------------------------------------------------
// {stag, qtag}->BD mapping
//--------------------------------------------------------
#ifndef __p4c__
@pragma ignore_table_dependency port_vlan_to_bd_mapping
#endif
table port_qinq_to_bd_mapping {
    reads {
        ingress_metadata.port_lag_index : exact;
        vlan_tag_[0].vid : exact;
        vlan_tag_[1].vid : exact;
    }
    action_profile: bd_action_profile;
#ifdef __p4c__
    const default_action: nop();
#endif
    size : QINQ_RIF_TABLE_SIZE;
}

#endif /* QINQ_RIF_ENABLE */                    
//--------------------------------------------------------
// BD properties for cpu-tx packets
//--------------------------------------------------------
@pragma ignore_table_dependency my_sid
table cpu_packet_transform {
    reads {
        fabric_header_cpu.ingressBd mask 0xFFF: exact;
        // One entry for every vlan
    }
    action_profile: bd_action_profile;
#ifdef __p4c__
    const default_action: nop();
#endif
    size : BD_TABLE_SIZE;
}

//-------------------------------
// ifindex properties
//-------------------------------
action_profile ifindex_action_profile {
    actions {
        ifindex_properties;
    }
    size : PORT_TABLE_SIZE;
}

action ifindex_properties(ifindex) {
    modify_field(ingress_metadata.ifindex, ifindex);
    modify_field(l2_metadata.same_if_check, ifindex);
}

//-------------------------------
// ifindex derivation 
//-------------------------------
table ifindex_mapping {
    reads {
        fabric_header_cpu : valid;
        fabric_header_cpu.ingressPort : ternary;
        ig_intr_md.ingress_port : exact;
        // Two entries for every port
        // {true , port, cpu_port }
        // {false,    *, port}
    }
    actions {
        ifindex_properties;
    }
    default_action: ifindex_properties(0);
    size : INGRESS_IFINDEX_TABLE_SIZE;
}

//-------------------------------------
// ifindex derivation for L2 sub-ports
//-------------------------------------
#ifdef BRIDGE_SUB_PORT_ENABLE
action port_vlan_to_ifindex_miss() {
}

table port_vlan_to_ifindex_mapping {
    reads {
        ingress_metadata.port_lag_index : exact;
        vlan_tag_[0] : valid;
        vlan_tag_[0].vid : exact;
    }

    action_profile: ifindex_action_profile;
    size : PORT_VLAN_TABLE_SIZE;
}
#endif /* BRIDGE_SUB_PORT_ENABLE */

//-------------------------------------------
// Control flow for BD/Interface derivation
//------------------------------------------
control process_port_vlan_mapping {
    // BD Derivation
    if(valid(fabric_header_cpu)) {
        apply(cpu_packet_transform);
    } else {
        apply(port_vlan_to_bd_mapping) {
#ifdef QINQ_RIF_ENABLE            
            miss {
                apply(port_qinq_to_bd_mapping) {
#endif /* QINQ_RIF_ENABLE */                    
                    miss {
                        apply(vlan_to_bd_mapping);
                    }
#ifdef QINQ_RIF_ENABLE            
                }
            }
#endif /* QINQ_RIF_ENABLE */                    
        }
    }
        
    // ifindex Derivation
    apply(ifindex_mapping);

    // Copy outer packet metadata to lkup fields
#if defined(TUNNEL_DISABLE) && !defined(TUNNEL_PARSING_DISABLE)
    apply(adjust_lkp_fields);
#endif
}

/*****************************************************************************/
// Ingress vlan membership check
/*****************************************************************************/

register ingress_vlan_mbr_reg{
    width : 1;
    static : ingress_vlan_mbr;
    instance_count : VLAN_MBR_TABLE_SIZE;
}

blackbox stateful_alu ingress_vlan_mbr_alu{
    reg: ingress_vlan_mbr_reg;
    update_lo_1_value: read_bitc;
    output_value: alu_lo;
    output_dst: l2_metadata.ingress_vlan_mbr_check_fail;
}


@pragma field_list_field_slice ig_intr_md.ingress_port 6 0 // Ports 0-71 ( local to the pipeline )
@pragma field_list_field_slice ingress_metadata.bd 11 0 // First 4K BDs which are reserved for VLANs
field_list ingress_pv_fields {
    ig_intr_md.ingress_port;
    ingress_metadata.bd;
}

field_list_calculation ingress_pv_hash {
    input { ingress_pv_fields; }
    algorithm { identity; }
    output_width : 19;
}

action ingress_vlan_mbr_check() {
    ingress_vlan_mbr_alu.execute_stateful_alu_from_hash(ingress_pv_hash);
}

table ingress_vlan_mbr {
    actions { ingress_vlan_mbr_check; }
    default_action : ingress_vlan_mbr_check;
    size : 1;
}

control process_ingress_vlan_mbr {
    if (((ingress_metadata.bd & 0x3000) == 0) and (tunnel_metadata.tunnel_terminate==0)) {
        apply(ingress_vlan_mbr);
    }
}

/*****************************************************************************/
/* Ingress BD stats based on packet type                                     */
/*****************************************************************************/
#ifndef STATS_DISABLE
#ifdef ALT_PKT_VALIDATE_ENABLE
counter ingress_bd_stats {
  type : packets_and_bytes;
  direct : ingress_bd_stats;
  min_width : 32;
}

table ingress_bd_stats {
  reads {
    ingress_metadata.bd : exact;
    l2_metadata.lkp_pkt_type: exact;  
  }
  actions {
    nop;
  }
  size : BD_STATS_TABLE_SIZE;
}
#else
counter ingress_bd_stats {
    type : packets_and_bytes;
    instance_count : BD_STATS_TABLE_SIZE;
    min_width : 32;
}

action update_ingress_bd_stats() {
    count(ingress_bd_stats, l2_metadata.bd_stats_idx);
}

table ingress_bd_stats {
    actions {
        update_ingress_bd_stats;
    }
    default_action : update_ingress_bd_stats;
    size : BD_STATS_TABLE_SIZE;
}
#endif /* ALT_PKT_VALIDATE_ENABLE */
#endif /* STATS_DISABLE */

control process_ingress_bd_stats {
#ifndef STATS_DISABLE
    apply(ingress_bd_stats);
#endif /* STATS_DISABLE */
}


/*****************************************************************************/
/* LAG lookup/resolution                                                     */
/*****************************************************************************/
field_list lag_hash_fields {
#if defined(RESILIENT_HASH_ENABLE)
#ifndef HASH_32BIT_ENABLE
    hash_metadata.hash1;
    hash_metadata.hash2;
#endif
    hash_metadata.hash1;
#endif /* RESILIENT_HASH_ENABLE */
    hash_metadata.hash2;
#ifdef FLOWLET_ENABLE
    flowlet_metadata.id;
#endif /* FLOWLET_ENABLE */
}

field_list_calculation lag_hash {
    input {
        lag_hash_fields;
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

action_selector lag_selector {
    selection_key : lag_hash;
#ifdef RESILIENT_HASH_ENABLE
    selection_mode : resilient;
#else
    selection_mode : fair;
#endif /* RESILIENT_HASH_ENABLE */
}

#ifdef FABRIC_ENABLE
action set_lag_remote_port(device, port) {
    modify_field(fabric_metadata.dst_device, device);
    modify_field(fabric_metadata.dst_port, port);
}
#endif /* FABRIC_ENABLE */

#ifdef FAST_FAILOVER_ENABLE
action set_lag_port(port, fallback_check) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
    modify_field(failover_metadata.fallback_check, fallback_check);
}
#else
action set_lag_port(port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}
#endif /* FAST_FAILOVER_ENABLE */

action set_lag_miss() {
}

action_profile lag_action_profile {
    actions {
        set_lag_miss;
        set_lag_port;
#ifdef FABRIC_ENABLE
        set_lag_remote_port;
#endif /* FABRIC_ENABLE */
    }
    size : LAG_GROUP_TABLE_SIZE;
    dynamic_action_selection : lag_selector;
}

table lag_group {
    reads {
        ingress_metadata.egress_port_lag_index : exact;
    }
    action_profile: lag_action_profile;
    size : LAG_SELECT_TABLE_SIZE;
}

#ifdef MLAG_ENABLE
action set_peer_link_port(port, ifindex) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    bit_xor(l2_metadata.same_if_check, l2_metadata.same_if_check, ifindex);
}

action set_peer_link_miss() {
}

action_profile peer_link_action_profile {
    actions {
        set_peer_link_miss;
        set_peer_link_port;
    }
    size : LAG_GROUP_TABLE_SIZE;
    dynamic_action_selection : lag_selector;
}

#ifndef Q0_PROFILE
@pragma ternary 1
#endif
table peer_link_group {
    reads {
        ingress_metadata.egress_port_lag_index : exact;
    }
    action_profile: peer_link_action_profile;
    size : LAG_SELECT_TABLE_SIZE;
}
#endif /* MLAG_ENABLE */

control process_lag {
#ifdef FAST_FAILOVER_ENABLE
    if (valid(pktgen_port_down)) {
        apply(lag_failover);
        apply(lag_failover_recirc);
    } else {
#endif
#ifdef MLAG_ENABLE
        apply(lag_group) {
            set_lag_miss {
                apply(peer_link_group);
            }
        }
#else
        apply(lag_group);
#endif
#ifdef FAST_FAILOVER_ENABLE
    }
#endif /* FAST_FAILOVER_ENABLE */
}


/*****************************************************************************/
/* Egress port lookup                                                        */
/*****************************************************************************/
#ifdef EGRESS_PORT_MIRROR_OPTIMIZATION
action egress_port_type_normal(qos_group, port_lag_label, mlag_member, session_id) {
#else    
action egress_port_type_normal(qos_group, port_lag_label, mlag_member) {
#endif
    modify_field(egress_metadata.port_type, PORT_TYPE_NORMAL);
#ifndef GLOBAL_EGRESS_QOS_MARKING_ENABLE
    modify_field(qos_metadata.egress_qos_group, qos_group);
#endif
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
    modify_field(acl_metadata.egress_port_lag_label, port_lag_label);
#ifdef MLAG_ENABLE
    modify_field(l2_metadata.egress_port_is_mlag_member, mlag_member);
#endif /* MLAG_PRUNING */
#ifdef EGRESS_PORT_MIRROR_OPTIMIZATION
    set_egress_port_mirror_index(session_id);    
#endif
#ifdef CALCULATE_LATENCY_OPTIMIZATION_ENABLE
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) || defined(INT_DIGEST_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)
    calculate_latency();
#endif /* DTEL_FLOW_STATE_TRACK_ENABLE || INT_DIGEST_DISABLE ||
        * DTEL_QUEUE_REPORT_ENABLE */
#endif /* CALCULATE_LATENCY_OPTIMIZATION_ENABLE */
}

action egress_port_type_fabric() {
#if defined(FABRIC_ENABLE)
    modify_field(egress_metadata.port_type, PORT_TYPE_FABRIC);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_FABRIC);
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
#endif /* FABRIC_ENABLE */
}

action egress_port_type_recirc() {
    modify_field(egress_metadata.port_type, PORT_TYPE_RECIRC);
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
    cpu_rx_rewrite();
#ifdef CALCULATE_LATENCY_OPTIMIZATION_ENABLE
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) || defined(INT_DIGEST_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)
    calculate_latency();
#endif /* DTEL_FLOW_STATE_TRACK_ENABLE || INT_DIGEST_DISABLE ||
        * DTEL_QUEUE_REPORT_ENABLE */
#endif /* CALCULATE_LATENCY_OPTIMIZATION_ENABLE */
}

action egress_port_type_cpu() {
    modify_field(egress_metadata.port_type, PORT_TYPE_CPU);
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
    cpu_rx_rewrite();
#ifdef CALCULATE_LATENCY_OPTIMIZATION_ENABLE
#if defined(DTEL_FLOW_STATE_TRACK_ENABLE) || defined(INT_DIGEST_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)
    calculate_latency();
#endif /* DTEL_FLOW_STATE_TRACK_ENABLE || INT_DIGEST_DISABLE ||
        * DTEL_QUEUE_REPORT_ENABLE */
#endif /* CALCULATE_LATENCY_OPTIMIZATION_ENABLE */
}

#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
@pragma ternary 1
#endif
table egress_port_mapping {
    reads {
        eg_intr_md.egress_port : exact;
    }
    actions {
        egress_port_type_normal;
#if defined(FABRIC_ENABLE)
        egress_port_type_fabric;
#endif
        egress_port_type_cpu;
#ifdef COPY_TO_CPU_USING_RECIRC
        egress_port_type_recirc;
#endif
    }
    size : PORT_TABLE_SIZE;
}


/*****************************************************************************/
/* Egress VLAN translation                                                   */
/*****************************************************************************/
#ifdef QINQ_ENABLE
action set_egress_if_params_qinq_tagged(s_tag) {
    copy_header(vlan_tag_[1], vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ETHERTYPE_VLAN);
    modify_field(vlan_tag_[0].vid, s_tag);
    modify_field(ethernet.etherType, ETHERTYPE_QINQ);
}
action set_egress_if_params_qinq_tagged_with_bd_as_stag() {
    copy_header(vlan_tag_[1], vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ETHERTYPE_VLAN);
    modify_field(vlan_tag_[0].vid, egress_metadata.outer_bd, 0xFFF);
    modify_field(ethernet.etherType, ETHERTYPE_QINQ);
}
#endif

action set_egress_if_params_tagged(vlan_id) {
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ethernet.etherType);
    modify_field(vlan_tag_[0].vid, vlan_id);
    modify_field(ethernet.etherType, ETHERTYPE_VLAN);
}
action set_egress_if_params_tagged_with_bd_as_vlan() {
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ethernet.etherType);
    modify_field(vlan_tag_[0].vid, egress_metadata.outer_bd, 0xFFF);
    modify_field(ethernet.etherType, ETHERTYPE_VLAN);
}

action set_egress_if_params_untagged() {
}

#ifdef QINQ_RIF_ENABLE
action set_egress_if_params_double_tagged(vlan_id0, vlan_id1) {
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ETHERTYPE_VLAN);
    modify_field(vlan_tag_[0].vid, vlan_id0);
    add_header(vlan_tag_[1]);
    modify_field(vlan_tag_[1].etherType, ethernet.etherType);
    modify_field(vlan_tag_[1].vid, vlan_id1);
    modify_field(ethernet.etherType, ETHERTYPE_QINQ);
}
#endif /* QINQ_RIF_ENABLE */    
    
#if defined(GENERIC_INT_LEAF_PROFILE)
@pragma stage 10
#endif

table egress_vlan_xlate {
    reads {
        eg_intr_md.egress_port : ternary;
        egress_metadata.outer_bd : ternary;
        vlan_tag_[0] : valid;
        // {port, BD, *} -> nop entry for every L3-interface
        // {port, BD, *} -> set_tagged entry for every L3-sub-interface
        // {port, BD, *} -> nop entry for access ports
        // {port, native-vlan-BD, 0} -> nop for trunk ports with untagged native_vlan OR
        // {port, native-vlan-BD, 0} -> set_tagged for trunk ports with tagged native_vlan
        // {port, *, 1} -> qinq_tagged_with_bd_as_vlan entry for every trunk port (packet arrived on qinq tunnel port)
        // {port, *, 0} -> set_tagged_with_bd_as_vlan entry for every trunk port 
    }
    actions {
        set_egress_if_params_untagged;
        set_egress_if_params_tagged;
        set_egress_if_params_tagged_with_bd_as_vlan;
#ifdef QINQ_ENABLE
        set_egress_if_params_qinq_tagged;
        set_egress_if_params_qinq_tagged_with_bd_as_stag;
#endif
    }
    size : EGRESS_VLAN_XLATE_TABLE_SIZE;
}

#ifdef QINQ_RIF_ENABLE
table bd_to_qinq_mapping {
    reads {
        eg_intr_md.egress_port : exact;
        egress_metadata.outer_bd : exact;
        // {port, BD} -> one set_double_tagged entry for every QinQ RIF
    }
    actions {
        set_egress_if_params_double_tagged;
    }
    size : QINQ_RIF_TABLE_SIZE;
}
#endif /* QINQ_RIF_ENABLE */    

control process_vlan_xlate {
#ifdef QINQ_RIF_ENABLE
    apply(bd_to_qinq_mapping) {
        miss {
            apply(egress_vlan_xlate);
        }
    }
#else
    apply(egress_vlan_xlate);
#endif /* QINQ_RIF_ENABLE */    
}

/*****************************************************************************/
/* Overwrite RID for packets coming on peer-link */
/*****************************************************************************/
#if defined(MLAG_ENABLE)
action set_peer_link_properties() {
    modify_field(ig_intr_md_for_tm.rid, ALL_RID_DEFAULT);
    modify_field(l2_metadata.ingress_port_is_peer_link, TRUE);
}

table peer_link_properties {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_peer_link_properties;
    }
    size : PORT_TABLE_SIZE;
}
#endif /* MLAG_PRUNING */

control process_peer_link_properties {
#if defined(MLAG_ENABLE)
    apply(peer_link_properties);
#endif /* MLAG_PRUNING */
}

/*****************************************************************************/
/* capture timestamp                                                         */
/*****************************************************************************/
#ifdef PTP_ENABLE
action set_capture_tstamp() {
    modify_field(eg_intr_md_for_oport.capture_tstamp_on_tx, egress_metadata.capture_tstamp_on_tx);
}

table capture_tstamp {
    actions {
        set_capture_tstamp;
    }
    default_action : set_capture_tstamp;
    size : 1;
}
#endif /* PTP_ENABLE */
