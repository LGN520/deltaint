
/*****************************************************************************/
/* Qos Processing                                                            */
/*****************************************************************************/

header_type qos_metadata_t {
    fields {
        ingress_qos_group: 5;
        tc_qos_group: 5;
        egress_qos_group: 5;
#if defined(GENERIC_INT_LEAF_PROFILE) || defined(L3_HEAVY_INT_LEAF_PROFILE) \
      || defined(GENERIC_INT_SPINE_PROFILE) || defined(L3_HEAVY_INT_SPINE_PROFILE) \
      || defined(SRV6_L3VPN_PROFILE) || defined(L3_INT_LEAF_PROFILE)
        lkp_tc: 9;
#else
        lkp_tc: 8;
#endif
        trust_dscp: 1;
        trust_pcp: 1;
    }
}

metadata qos_metadata_t qos_metadata;

#if defined(QOS_METERING_ENABLE) && !defined(QOS_METER_IN_MAP_TABLE_DISABLE)
#define INGRESS_QOS_MAP_ACTIONS \
        nop; \
        set_ingress_tc; \
        set_ingress_color; \
        set_ingress_tc_and_color; \
	set_ingress_tc_color_and_meter;
#else
#define INGRESS_QOS_MAP_ACTIONS \
        nop; \
        set_ingress_tc; \
        set_ingress_color; \
        set_ingress_tc_and_color;
#endif /* QOS_METERING_ENABLE */

/*****************************************************************************/
/* Ingress QOS Map                                                           */
/*****************************************************************************/
#ifdef QOS_CLASSIFICATION_ENABLE
#if defined(QOS_METERING_ENABLE) && !defined(QOS_METER_IN_MAP_TABLE_DISABLE)
action set_ingress_tc_color_and_meter(tc, color, qos_meter_index) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(ig_intr_md_for_tm.packet_color, color);
    modify_field(meter_metadata.meter_index, qos_meter_index);
}
#endif /* QOS_METERING_ENABLE */

action set_ingress_tc_and_color(tc, color) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(ig_intr_md_for_tm.packet_color, color);
}

action set_ingress_tc(tc) {
    modify_field(qos_metadata.lkp_tc, tc);
}

action set_ingress_color(color) {
  modify_field(ig_intr_md_for_tm.packet_color, color);
}

table ingress_qos_map_dscp {
    reads {
        qos_metadata.ingress_qos_group: ternary;
        l3_metadata.lkp_dscp: ternary;
    }

    actions {
        INGRESS_QOS_MAP_ACTIONS
    }

    size: DSCP_TO_TC_AND_COLOR_TABLE_SIZE;
}

table ingress_qos_map_pcp {
    reads {
        qos_metadata.ingress_qos_group: ternary;
        l2_metadata.lkp_pcp: ternary;
    }

    actions {
        INGRESS_QOS_MAP_ACTIONS
    }

    size: PCP_TO_TC_AND_COLOR_TABLE_SIZE;
}

#endif /* QOS_CLASSIFICATION_ENABLE */

#if !defined(QOS_CLASSIFICATION_ENABLE) && defined(SS_QOS_CLASSIFICATION_ENABLE)
action set_ingress_qid_and_tc_and_color(tc, icos, qid, color) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.packet_color, color);
}

table ingress_qos_map {
    reads {
        qos_metadata.ingress_qos_group: ternary;
        l3_metadata.lkp_dscp: ternary;
        l2_metadata.lkp_pcp: ternary;
        qos_metadata.trust_dscp: ternary;
        qos_metadata.trust_pcp: ternary;
      // Following fields may be needed in the match key if we want to
      // take care of these corner cases :
      // -- trust_dscp is enabled, incoming packet is non-IP and port-default
      //    policy is different than dscp=0 policy
      // -- trust_cos is enabled, incoming packet doesn't have a vlan tag
      //    and port-default policy is different than PCP=0 policy
//        ipv4: valid;
//        ipv6: valid;
//        vlan_tag_[0]: valid;
     }

    actions {
         nop;
         set_ingress_qid_and_tc_and_color;
    }
    size: INGRESS_QOS_MAP_TABLE_SIZE;
}
#endif /* SS_QOS_CLASSIFICATION_ENABLE */

control process_ingress_qos_map {
    if (DO_LOOKUP(QOS)) {
#if defined(QOS_CLASSIFICATION_ENABLE)
#if defined(QOS_ACL_ENABLE)
      if ((qos_metadata.trust_dscp == TRUE) and (l3_metadata.lkp_ip_type == IPTYPE_IPV4)) {
        apply(ipv4_qos_acl);
#ifndef IPV6_DISABLE
      } else if ((qos_metadata.trust_dscp == TRUE) and (l3_metadata.lkp_ip_type == IPTYPE_IPV6)) {
        apply(ipv6_qos_acl);
#endif /* IPV6_DISABLE */
      } else if ((qos_metadata.trust_pcp == TRUE) and ((valid(vlan_tag_[0])) or (ingress_metadata.port_type == PORT_TYPE_CPU))) {
        apply(mac_qos_acl);
      }
#else
      if ((qos_metadata.trust_dscp == TRUE) and (l3_metadata.lkp_ip_type != IPTYPE_NONE)) {
        apply(ingress_qos_map_dscp);
      } else if ((qos_metadata.trust_pcp == TRUE) and ((valid(vlan_tag_[0])) or (ingress_metadata.port_type == PORT_TYPE_CPU))) {
        apply(ingress_qos_map_pcp);
      }
#endif /* QOS_ACL_ENABLE */
#elif defined(SS_QOS_CLASSIFICATION_ENABLE)
	apply(ingress_qos_map);
#endif /* SS_QOS_CLASSIFICATION_ENABLE */
    }
}


/*****************************************************************************/
/* Queuing                                                                   */
/*****************************************************************************/

#ifdef QOS_CLASSIFICATION_ENABLE
action set_icos(icos) {
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
}

action set_queue(qid) {
    modify_field(ig_intr_md_for_tm.qid, qid);
}

action set_icos_and_queue(icos, qid) {
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(ig_intr_md_for_tm.qid, qid);
}

table traffic_class {
    reads {
#ifndef GLOBAL_TC_ICOS_QUEUE_TABLE
        qos_metadata.tc_qos_group: ternary;
#endif
        qos_metadata.lkp_tc: ternary;
#if defined(COLOR_IN_TRAFFIC_CLASS_ENABLE) && defined(QOS_METERING_ENABLE)
        ig_intr_md_for_tm.packet_color: ternary;
#endif
    }

    actions {
        nop;
        set_icos;
        set_queue;
        set_icos_and_queue;
    }
    size: QUEUE_TABLE_SIZE;
}
#endif /* QOS_CLASSIFICATION_ENABLE */

control process_traffic_class{
#ifdef QOS_CLASSIFICATION_ENABLE
    apply(traffic_class);
#endif /* QOS_CLASSIFICATION_ENABLE */
}

/*****************************************************************************/
/* Egress QOS Map                                                            */
/*****************************************************************************/
#if defined(QOS_MARKING_ENABLE)
//action set_mpls_exp_marking(exp) {
//    modify_field(l3_metadata.lkp_dscp, exp, 0xfc);
//}

action set_ipv4_dscp_marking(dscp) {
    modify_field(ipv4.diffserv, dscp, 0xfc);
}

action set_pcp_ipv4_dscp_marking(pcp,dscp) {
    modify_field(ipv4.diffserv, dscp, 0xfc);
    modify_field(vlan_tag_[0].pcp, pcp);
}

#ifndef IPV6_DISABLE
action set_ipv6_dscp_marking(dscp) {
    modify_field(ipv6.trafficClass, dscp, 0xfc);
}

action set_pcp_ipv6_dscp_marking(pcp,dscp) {
    modify_field(ipv6.trafficClass, dscp, 0xfc);
    modify_field(vlan_tag_[0].pcp, pcp);
}
#endif

action set_vlan_pcp_marking(pcp) {
    modify_field(vlan_tag_[0].pcp, pcp);
}

table egress_qos_map {
    reads {
#ifndef GLOBAL_EGRESS_QOS_MARKING_ENABLE
        qos_metadata.egress_qos_group: ternary;
#endif
        qos_metadata.lkp_tc: ternary;
#ifdef QOS_METERING_ENABLE
        ig_intr_md_for_tm.packet_color : ternary;
#endif
        ipv4.valid : ternary;
#ifndef IPV6_DISABLE
        ipv6.valid : ternary;
#endif
    }
    actions {
        nop;
        //set_mpls_exp_marking;
        set_ipv4_dscp_marking;
        set_pcp_ipv4_dscp_marking;
#ifndef IPV6_DISABLE
        set_ipv6_dscp_marking;
        set_pcp_ipv6_dscp_marking;
#endif
        set_vlan_pcp_marking;
    }
    size: EGRESS_QOS_MAP_TABLE_SIZE;
}
#endif /* QOS_MARKING_ENABLE */

control process_egress_qos_map {
#if defined(QOS_MARKING_ENABLE)
    if (DO_LOOKUP(QOS)) {
        apply(egress_qos_map);
    }
#endif /* QOS_MARKING_ENABLE */
}

/*****************************************************************************/
/* Egress Queue Stats                                                        */
/*****************************************************************************/
counter egress_queue_stats {
    type : packets_and_bytes;
    direct : egress_queue_stats;
}

table egress_queue_stats {
    reads {
        eg_intr_md.egress_port : exact;
        ig_intr_md_for_tm.qid : exact ;
    }
    actions {
        nop;
    }
    default_action: nop();
    size : EGRESS_QUEUE_STATS_TABLE_SIZE;
}

control process_egress_queue_stats {
#ifdef EGRESS_QUEUE_STATS_ENABLE
  /* Note : This logic doesn't take care of packets dropped or sent to cpu by egress system acl */
  apply(egress_queue_stats);
#endif /* EGRESS_QUEUE_STATS_ENABLE */
}

/*****************************************************************************/
/* Ingress PPG Stats                                                        */
/*****************************************************************************/
counter ingress_ppg_stats {
    type : packets_and_bytes;
    direct : ingress_ppg_stats;
}

table ingress_ppg_stats {
    reads {
        ingress_metadata.ingress_port : exact;
        ig_intr_md_for_tm.ingress_cos : exact ;
#ifdef PFC_ACL_ENABLE
        ig_intr_md_for_tm.drop_ctl mask 0x1 : exact;
#endif
    }
    actions {
        nop;
    }
    default_action: nop();
    size : INGRESS_PPG_STATS_TABLE_SIZE;
}

control process_ingress_ppg_stats {
#ifdef INGRESS_PPG_STATS_ENABLE
  /* Note : This logic doesn't take care of packets dropped or sent to cpu by system acl */
  apply(ingress_ppg_stats);
#endif /* INGRESS_PPG_STATS_ENABLE */
}

/*****************************************************************************/
/* ingress pfc acl                                                           */
/*****************************************************************************/
action pfc_acl_drop() {
    drop();
}

table ingress_pfc_acl {
    reads {
        ig_intr_md.ingress_port : exact;
        ig_intr_md_for_tm.qid : exact;
    }

    actions {
        nop;
        pfc_acl_drop;
    }

    default_action : nop();
    size : INGRESS_PFC_ACL_TABLE_SIZE;
}

/*****************************************************************************/
/* egress pfc acl                                                           */
/*****************************************************************************/
counter pfc_acl_stats {
    type : packets_and_bytes;
    direct : egress_pfc_acl;
}

table egress_pfc_acl {
    reads {
        eg_intr_md.egress_port : exact;
        ig_intr_md_for_tm.qid : exact;
    }

    actions {
        nop;
        pfc_acl_drop;
    }

    default_action : nop();
    size : EGRESS_PFC_ACL_TABLE_SIZE;
}

control process_egress_pfc_acl {
#ifdef PFC_ACL_ENABLE
  apply(egress_pfc_acl);
#endif
}
