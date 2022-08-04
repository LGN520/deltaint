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
 * ACL processing : MAC, IPv4, IPv6, RACL/PBR
 */

/*
 * ACL metadata
 */
header_type acl_metadata_t {
    fields {
        acl_deny : 1;                          /* ifacl/vacl deny action */
        racl_deny : 1;                         /* racl deny action */
        egress_acl_deny : 1;                   /* egress acl deny action */
#ifndef FWD_RESULTS_OPTIMIZATION_ENABLE
        acl_nexthop : NEXTHOP_BIT_WIDTH;       /* next hop from ifacl/vacl */
        racl_nexthop : NEXTHOP_BIT_WIDTH;      /* next hop from racl */
        acl_nexthop_type : 1;                  /* ecmp or nexthop */
        racl_nexthop_type : 1;                 /* ecmp or nexthop */
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
        acl_redirect :   1;                    /* ifacl/vacl redirect action */
        racl_redirect : 1;                     /* racl redirect action */
        port_lag_label : PORT_LABEL_WIDTH;	   /* port/lag label for acls */
        //if_label : 16;                         /* if label for acls */
        bd_label : 16;                         /* bd label for acls */
        acl_stats_index : 12;                  /* acl stats index */
        mirror_acl_stats_index : 10;           /* mirror acl stats index */
        egress_mirror_acl_stats_index : 10;    /* egress mirror acl stats index */
        racl_stats_index : 12;                 /* ingress racl stats index */
        egress_acl_stats_index : 12;           /* egress acl stats index */
        dtel_acl_stats_index : 12;             /* dtel acl stats index */
        acl_partition_index : 16;              /* acl atcam partition index */
        egress_port_lag_label : 16;	           /* port/lag label for acls */
        //egress_if_label : 16;                  /* if label for egress acls */
        egress_bd_label : 16;                  /* bd label for egress acls */
        ingress_src_port_range_id : 8;         /* ingress src port range id */
        ingress_dst_port_range_id : 8;         /* ingress dst port range id */
        egress_src_port_range_id : 8;          /* egress src port range id */
        egress_dst_port_range_id : 8;          /* egress dst port range id */
        copp_meter_id : 8;                     /* copp meter-id */
        copp_meter_id_2 : 8;                     /* copp meter-id for system_acl_2 */
        mac_pkt_classify : 1;                  /* enables MAC-packet classify */
        acl_entry_hit : 1;                     /* user ACL hit bit */
        acl_label        : 8;                  
        inner_outer_ip_type : 2;               /* inner if exists, else outer */
        inner_outer_etype   : 16;              /* inner if exists, else outer */
        inner_outer_ipv4_sa : 32;              /* inner if exists, else outer */
        inner_outer_ipv4_da : 32;              /* inner if exists, else outer */
        inner_outer_ipv6_sa : 128;             /* inner if exists, else outer */
        inner_outer_ipv6_da : 128;             /* inner if exists, else outer */
        inner_outer_ip_proto : 8;              /* inner if exists, else outer */
        inner_outer_ip_dscp : 8;               /* inner if exists, else outer */
        inner_outer_ip_sport : 16;             /* inner if exists, else outer */
        inner_outer_ip_dport : 16;             /* inner if exists, else outer */
        inner_outer_src_port_range_id : 8;     /* inner if exists, else outer */
        inner_outer_dst_port_range_id : 8;     /* inner if exists, else outer */
        inner_outer_is_inner: 1;               /* 1 indicates inner fields */
        compact_ipv6_flow_label : 8;           /* reduced IPV6 flow-label */
    }
}

#define INGRESS_ACL_KEY_INPUT_PORT       ig_intr_md.ingress_port
#define INGRESS_ACL_KEY_OUTPUT_PORT      ig_intr_md_for_tm.ucast_egress_port
#define INGRESS_ACL_KEY_DROP_FLAG        ingress_metadata.drop_flag
#define INGRESS_ACL_KEY_DROP_REASON      ingress_metadata.drop_reason
#define INGRESS_ACL_KEY_ARP_OPCODE       l2_metadata.arp_opcode
#define INGRESS_ACL_KEY_STP_STATE        l2_metadata.ingress_stp_check_fail
#define INGRESS_ACL_KEY_FIB_HIT          l3_metadata.fib_hit
#define INGRESS_ACL_KEY_ACL_LABEL        acl_metadata.acl_label
#define INGRESS_ACL_KEY_DMAC_LABEL       l2_metadata.dmac_label
#define INGRESS_ACL_KEY_FIB_LABEL        l3_metadata.fib_label
#define INGRESS_ACL_KEY_TUNNEL_TYPE      tunnel_metadata.ingress_tunnel_type
#define INGRESS_ACL_KEY_PORT_LABEL       acl_metadata.port_lag_label
#define INGRESS_ACL_KEY_BD_LABEL         acl_metadata.bd_label
#define INGRESS_ACL_KEY_MAC_SA           l2_metadata.lkp_mac_sa
#define INGRESS_ACL_KEY_MAC_DA           l2_metadata.lkp_mac_da
#define INGRESS_ACL_KEY_PCP              l2_metadata.lkp_pcp
#define INGRESS_ACL_KEY_CFI              l2_metadata.lkp_cfi
#define INGRESS_ACL_KEY_ETYPE            l2_metadata.lkp_mac_type
#define INGRESS_ACL_KEY_IP_TYPE          l3_metadata.lkp_ip_type
#define INGRESS_ACL_KEY_IPV4_SA          ipv4_metadata.lkp_ipv4_sa
#define INGRESS_ACL_KEY_IPV4_DA          ipv4_metadata.lkp_ipv4_da
#define INGRESS_ACL_KEY_IPV6_SA          ipv6_metadata.lkp_ipv6_sa
#define INGRESS_ACL_KEY_IPV6_DA          ipv6_metadata.lkp_ipv6_da
#define INGRESS_ACL_KEY_IPV6_FLOWLABEL   acl_metadata.compact_ipv6_flow_label
#define INGRESS_ACL_KEY_IP_PROTO         l3_metadata.lkp_ip_proto
#define INGRESS_ACL_KEY_IP_DSCP          l3_metadata.lkp_dscp
#define INGRESS_ACL_KEY_IP_TTL           l3_metadata.lkp_ip_ttl
#define INGRESS_ACL_KEY_VLAN_ID          vlan_tag_[0].vid
#define INGRESS_ACL_KEY_IP_FRAG          l3_metadata.lkp_ip_frag
#define INGRESS_ACL_KEY_TCP_FLAGS        l3_metadata.lkp_tcp_flags
#define INGRESS_ACL_KEY_SRC_PORT_RANGE   acl_metadata.ingress_src_port_range_id
#define INGRESS_ACL_KEY_DST_PORT_RANGE   acl_metadata.ingress_dst_port_range_id
#define INGRESS_ACL_KEY_L4_SRC_PORT      l3_metadata.lkp_l4_sport
#define INGRESS_ACL_KEY_L4_DST_PORT      l3_metadata.lkp_l4_dport
#define INGRESS_ACL_KEY_FC_SID           fcoe_fc.s_id
#define INGRESS_ACL_KEY_FC_DID           fcoe_fc.d_id
#define INGRESS_ACL_KEY_FIP_OPER_CODE    fip.oper_code
#define INGRESS_ACL_KEY_ROCEV2_OPCODE    l3_metadata.rocev2_opcode
#define INGRESS_ACL_KEY_ROCEV2_ACK_REQ_RSVD     l3_metadata.rocev2_ack_req_rsvd
#define INGRESS_ACL_KEY_ROCEV2_DST_QP_PLUS_RSVD l3_metadata.rocev2_dst_qp_plus_rsvd
#define INGRESS_ACL_KEY_ROCEV2_AETH_SYNDROME    l3_metadata.rocev2_aeth_syndrome
#define INGRESS_ACL_KEY_RMAC_HIT         l3_metadata.rmac_hit
#define INGRESS_ACL_KEY_QOS_GROUP                qos_metadata.ingress_qos_group
#define INGRESS_ACL_KEY_PACKET_COLOR       ig_intr_md_for_tm.packet_color
#define INGRESS_ACL_KEY_PKT_TYPE           l2_metadata.lkp_pkt_type
#define INGRESS_ACL_KEY_L2_DST_MISS        l2_metadata.l2_dst_miss
#define INGRESS_ACL_KEY_VLAN_MBR_CHECK_FAIL l2_metadata.ingress_vlan_mbr_check_fail
#define INGRESS_ACL_KEY_I_O_ETYPE        acl_metadata.inner_outer_etype
#define INGRESS_ACL_KEY_I_O_IPV4_SA      acl_metadata.inner_outer_ipv4_sa
#define INGRESS_ACL_KEY_I_O_IPV4_DA      acl_metadata.inner_outer_ipv4_da
#define INGRESS_ACL_KEY_I_O_IPV6_SA      acl_metadata.inner_outer_ipv6_sa
#define INGRESS_ACL_KEY_I_O_IPV6_DA      acl_metadata.inner_outer_ipv6_da
#define INGRESS_ACL_KEY_I_O_IP_PROTO     acl_metadata.inner_outer_ip_proto
#define INGRESS_ACL_KEY_I_O_IP_DSCP   acl_metadata.inner_outer_ip_dscp mask 0xFC
#define INGRESS_ACL_KEY_I_O_L4_SRC_PORT  acl_metadata.inner_outer_ip_sport
#define INGRESS_ACL_KEY_I_O_L4_DST_PORT  acl_metadata.inner_outer_ip_dport
#define INGRESS_ACL_KEY_I_O_SRC_PORT_RANGE acl_metadata.inner_outer_src_port_range_id
#define INGRESS_ACL_KEY_I_O_DST_PORT_RANGE acl_metadata.inner_outer_dst_port_range_id
#define INGRESS_ACL_KEY_I_O_IS_INNER     acl_metadata.inner_outer_is_inner

#define INGRESS_SYSTEM_FLOW_KEY \
        INGRESS_ACL_KEY_IPV6_DA     : ternary; \
        INGRESS_ACL_KEY_IPV4_DA     : ternary; \
        INGRESS_ACL_KEY_IPV4_SA     : ternary; \
        INGRESS_ACL_KEY_VLAN_ID     : ternary; \
        INGRESS_ACL_KEY_MAC_DA      : ternary; \
        INGRESS_ACL_KEY_ETYPE       : ternary; \
        INGRESS_ACL_KEY_IP_PROTO    : ternary; \
        INGRESS_ACL_KEY_IP_TTL      : ternary; \
        INGRESS_ACL_KEY_IP_DSCP     : ternary; \
        INGRESS_ACL_KEY_L4_SRC_PORT : ternary; \
        INGRESS_ACL_KEY_L4_DST_PORT : ternary; \
        fabric_metadata.reason_code : ternary;
//        INGRESS_ACL_KEY_IP_FRAGMENT : ternary; \

#define INGRESS_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_MAC_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary;

#define INGRESS_FCOE_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; \
        INGRESS_ACL_KEY_FC_SID           : ternary; \
        INGRESS_ACL_KEY_FC_DID           : ternary; \
        INGRESS_ACL_KEY_FIP_OPER_CODE    : ternary;

#define INGRESS_IPV4_ACL_KEY			    \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_TTL           : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_IPV6_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_TTL           : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;


#define INGRESS_MAC_QOS_ACL_KEY \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_PCP              : ternary; \

#define INGRESS_IPV4_QOS_ACL_KEY \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
      	INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_IPV6_QOS_ACL_KEY \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
      	INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_MAC_MIRROR_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; \
        INGRESS_ACL_KEY_PCP              : ternary; \

#define INGRESS_IPV4_MIRROR_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
      	INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_IPV6_MIRROR_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#ifdef TUNNEL_PARSING_DISABLE
#define INGRESS_IPV4_DTEL_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_I_O_IP_PROTO     : ternary;
#else
#define INGRESS_IPV4_DTEL_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_I_O_IS_INNER     : ternary; \
        INGRESS_ACL_KEY_I_O_IPV4_SA      : ternary; \
        INGRESS_ACL_KEY_I_O_IPV4_DA      : ternary; \
        INGRESS_ACL_KEY_I_O_IP_PROTO     : ternary;
#endif /* TUNNEL_PARSING_DISABLE */

#ifdef TUNNEL_PARSING_DISABLE
#define INGRESS_IPV6_DTEL_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_I_O_IP_PROTO     : ternary;
#else
#define INGRESS_IPV6_DTEL_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_I_O_IS_INNER     : ternary; \
        INGRESS_ACL_KEY_I_O_IPV6_SA      : ternary; \
        INGRESS_ACL_KEY_I_O_IPV6_DA      : ternary; \
        INGRESS_ACL_KEY_I_O_IP_PROTO     : ternary;
#endif /* TUNNEL_PARSING_DISABLE */

#define Q_PROFILES_INGRESS_SYSTEM_ACL_KEY \
        INGRESS_ACL_KEY_INPUT_PORT      : ternary; \
        INGRESS_ACL_KEY_MAC_SA          : ternary; \
        INGRESS_ACL_KEY_MAC_DA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA         : ternary; \
        INGRESS_ACL_KEY_IPV6_DA         : ternary; \
        INGRESS_ACL_KEY_DROP_FLAG       : ternary; \
        INGRESS_ACL_KEY_DROP_REASON     : ternary; \
        INGRESS_ACL_KEY_L4_SRC_PORT  : ternary; \
        INGRESS_ACL_KEY_L4_DST_PORT  : ternary; \
        INGRESS_ACL_KEY_ETYPE           : ternary; \
        INGRESS_ACL_KEY_IP_PROTO        : ternary; \
        INGRESS_ACL_KEY_IP_TTL          : ternary; \
        INGRESS_ACL_KEY_ARP_OPCODE      : ternary; \
        INGRESS_ACL_KEY_STP_STATE       : ternary; \
        INGRESS_ACL_KEY_FIB_HIT         : ternary; \
        INGRESS_ACL_KEY_OUTPUT_PORT     : ternary; \
        INGRESS_ACL_KEY_ACL_LABEL       : ternary; \
        INGRESS_ACL_KEY_DMAC_LABEL      : ternary; \
        INGRESS_ACL_KEY_FIB_LABEL       : ternary; \
        INGRESS_ACL_KEY_TUNNEL_TYPE     : ternary; \
        INGRESS_ACL_KEY_IP_TYPE         : ternary; \
        INGRESS_ACL_KEY_BD_LABEL        : ternary; \
        INGRESS_ACL_KEY_PORT_LABEL      : ternary; \
        INGRESS_ACL_KEY_IP_FRAG         : ternary;  \
        INGRESS_ACL_KEY_PACKET_COLOR    : ternary; \
        acl_metadata.acl_deny           : ternary; \
        acl_metadata.racl_deny          : ternary; \
        ig_intr_md_for_tm.drop_ctl      : ternary; \
        dtel_md.mod_watchlist_hit       : ternary; \
//        INGRESS_ACL_KEY_IPV6_FRAG : ternary;

#define INGRESS_SYSTEM_ACL_2_KEY \
        INGRESS_ACL_KEY_INPUT_PORT      : ternary; \
        INGRESS_ACL_KEY_DROP_FLAG       : ternary; \
        INGRESS_ACL_KEY_L4_SRC_PORT  : ternary; \
        INGRESS_ACL_KEY_L4_DST_PORT  : ternary; \
        INGRESS_ACL_KEY_ETYPE           : ternary; \
        INGRESS_ACL_KEY_IP_PROTO        : ternary; \
        INGRESS_ACL_KEY_IP_TTL          : ternary; \
        INGRESS_ACL_KEY_ARP_OPCODE      : ternary; \
        INGRESS_ACL_KEY_STP_STATE       : ternary; \
        INGRESS_ACL_KEY_FIB_HIT         : ternary; \
        INGRESS_ACL_KEY_OUTPUT_PORT     : ternary; \
        INGRESS_ACL_KEY_PKT_TYPE        : ternary; \
        INGRESS_ACL_KEY_FIB_LABEL       : ternary; \
        INGRESS_ACL_KEY_IP_TYPE         : ternary; \
        INGRESS_ACL_KEY_PORT_LABEL      : ternary; \
        INGRESS_ACL_KEY_L2_DST_MISS         : ternary; \
        INGRESS_ACL_KEY_PACKET_COLOR    : ternary; \

#define EGRESS_ACL_KEY_PORT_LABEL            acl_metadata.egress_port_lag_label
#define EGRESS_ACL_KEY_BD_LABEL              acl_metadata.egress_bd_label
#define EGRESS_ACL_KEY_MAC_SA                ethernet.srcAddr
#define EGRESS_ACL_KEY_MAC_DA                ethernet.dstAddr
#define EGRESS_ACL_KEY_ETYPE                 ethernet.etherType
#define EGRESS_ACL_KEY_IPV4_SA               ipv4.srcAddr
#define EGRESS_ACL_KEY_IPV4_DA               ipv4.dstAddr
#define EGRESS_ACL_KEY_IPV4_PROTO            ipv4.protocol
#define EGRESS_ACL_KEY_IPV4_DSCP             ipv4.diffserv
#define EGRESS_ACL_KEY_IPV6_SA               ipv6.srcAddr
#define EGRESS_ACL_KEY_IPV6_DA               ipv6.dstAddr
#define EGRESS_ACL_KEY_IPV6_PROTO            ipv6.nextHdr
#define EGRESS_ACL_KEY_IPV6_DSCP             ipv6.trafficClass

#ifdef PARSER_EXTRACT_OUTER_ENABLE
#define EGRESS_ACL_KEY_L4_SPORT              l3_metadata.lkp_l4_sport
#define EGRESS_ACL_KEY_L4_DPORT              l3_metadata.lkp_l4_dport
#else
#define EGRESS_ACL_KEY_L4_SPORT              l3_metadata.lkp_outer_l4_sport
#define EGRESS_ACL_KEY_L4_DPORT              l3_metadata.lkp_outer_l4_dport
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
#define EGRESS_ACL_KEY_L4_SPORT_RANGE        acl_metadata.egress_src_port_range_id
#define EGRESS_ACL_KEY_L4_DPORT_RANGE        acl_metadata.egress_dst_port_range_id
#define EGRESS_ACL_KEY_TCP_FLAGS             l3_metadata.lkp_tcp_flags

#define EGRESS_MAC_ACL_KEY \
        EGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        EGRESS_ACL_KEY_BD_LABEL         : ternary; \
        EGRESS_ACL_KEY_MAC_SA           : ternary; \
        EGRESS_ACL_KEY_MAC_DA           : ternary; \
        EGRESS_ACL_KEY_ETYPE            : ternary;

#define EGRESS_IPV4_ACL_KEY \
        EGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        EGRESS_ACL_KEY_BD_LABEL         : ternary; \
        EGRESS_ACL_KEY_IPV4_SA          : ternary; \
        EGRESS_ACL_KEY_IPV4_DA          : ternary; \
        EGRESS_ACL_KEY_IPV4_PROTO       : ternary;

#define EGRESS_IPV6_ACL_KEY \
        EGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        EGRESS_ACL_KEY_BD_LABEL         : ternary; \
        EGRESS_ACL_KEY_IPV6_SA          : ternary; \
        EGRESS_ACL_KEY_IPV6_DA          : ternary; \
        EGRESS_ACL_KEY_IPV6_PROTO       : ternary;

#if defined(QOS_METERING_ENABLE)
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

header_type i2e_metadata_t {
    fields {
        ingress_tstamp    : 32;
        ingress_tstamp_hi : 16;
        mirror_session_id : 16;
    }
}

#ifdef COALESCED_MIRROR_ENABLE
header_type coal_sample_hdr_t {
    // Small header (as an example) added to each coalesced sample
    fields {
        id: 32;
    }
}
header coal_sample_hdr_t coal_sample_hdr;
#endif

@pragma pa_solitary ingress INGRESS_ACL_KEY_PORT_LABEL
@pragma pa_atomic   ingress INGRESS_ACL_KEY_PORT_LABEL

#if defined(GENERIC_INT_LEAF_PROFILE)
@pragma pa_container_size ingress acl_metadata.bd_label 16
#endif
#if defined(GENERIC_INT_SPINE_PROFILE)
@pragma pa_container_size ingress acl_metadata.acl_redirect 8
#endif
#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
@pragma pa_do_not_bridge egress i2e_metadata.mirror_session_id
#endif
#if defined(DTEL_ACL_ENABLE) && defined(TUNNEL_PARSING_DISABLE)
@pragma pa_alias ingress acl_metadata.inner_outer_etype l2_metadata.lkp_mac_type
@pragma pa_alias ingress acl_metadata.inner_outer_ip_type l3_metadata.lkp_ip_type
@pragma pa_alias ingress acl_metadata.inner_outer_ip_proto l3_metadata.lkp_ip_proto
#if defined(M0_PROFILE)
@pragma pa_no_init ingress acl_metadata.inner_outer_ip_proto
#endif
@pragma pa_alias ingress acl_metadata.inner_outer_ip_dscp l3_metadata.lkp_dscp
@pragma pa_alias ingress acl_metadata.inner_outer_l4_sport l3_metadata.lkp_l4_sport
@pragma pa_alias ingress acl_metadata.inner_outer_l4_dport l3_metadata.lkp_l4_dport
@pragma pa_alias ingress acl_metadata.inner_outer_src_port_range_id acl_metadata.ingress_src_port_range_id
@pragma pa_alias ingress acl_metadata.inner_outer_dst_port_range_id acl_metadata.ingress_dst_port_range_id
#endif /* DTEL_ACL_ENABLE && TUNNEL_PARSING_DISABLE */
#if defined(Q0_PROFILE)
@pragma pa_container_size ingress acl_metadata.copp_meter_id 8
@pragma pa_container_size egress acl_metadata.egress_acl_deny 32
@pragma pa_container_size egress acl_metadata.egress_acl_stats_index 32
@pragma pa_container_size egress acl_metadata.egress_meter_index 32
@pragma pa_alias ingress acl_metadata.inner_outer_ipv4_sa ipv4_metadata.lkp_ipv4_sa
@pragma pa_alias ingress acl_metadata.inner_outer_ipv6_sa ipv6_metadata.lkp_ipv6_sa
@pragma pa_alias ingress acl_metadata.inner_outer_ip_dscp l3_metadata.lkp_dscp
@pragma pa_alias ingress acl_metadata.inner_outer_src_port_range_id acl_metadata.ingress_src_port_range_id
@pragma pa_alias ingress acl_metadata.inner_outer_dst_port_range_id acl_metadata.ingress_dst_port_range_id
#endif /* Q0_PROFILE */

#ifdef MSDC_IPV4_PROFILE
@pragma pa_no_overlay ingress acl_metadata.copp_meter_id
#endif

metadata acl_metadata_t acl_metadata;
metadata i2e_metadata_t i2e_metadata;

/*****************************************************************************/
/* Egress ACL l4 port range                                                  */
/*****************************************************************************/
#ifdef EGRESS_ACL_ENABLE
#if !defined(EGRESS_ACL_RANGE_DISABLE)
action set_egress_src_port_range_id(range_id) {
    modify_field(acl_metadata.egress_src_port_range_id, range_id);
}

table egress_l4_src_port {
    reads {
        EGRESS_ACL_KEY_L4_SPORT : range;
    }
    actions {
        nop;
        set_egress_src_port_range_id;
    }
    size: EGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_egress_dst_port_range_id(range_id) {
    modify_field(acl_metadata.egress_dst_port_range_id, range_id);
}

table egress_l4_dst_port {
    reads {
        EGRESS_ACL_KEY_L4_DPORT : range;
    }
    actions {
        nop;
        set_egress_dst_port_range_id;
    }
    size: EGRESS_ACL_RANGE_TABLE_SIZE;
}

#endif /* !EGRESS_ACL_RANGE_DISABLE */
#endif /* EGRESS_ACL_ENABLE */

control process_egress_l4port {
#ifdef EGRESS_ACL_ENABLE
#ifndef EGRESS_ACL_RANGE_DISABLE
    apply(egress_l4_src_port);
    apply(egress_l4_dst_port);
#endif /* EGRESS_ACL_RANGE_DISABLE */
#endif /* EGRESS_ACL_ENABLE */
}

/*****************************************************************************/
/* Ingress ACL l4 port range                                                 */
/*****************************************************************************/
#ifndef INGRESS_ACL_RANGE_DISABLE
action set_ingress_src_port_range_id(range_id) {
    modify_field(acl_metadata.ingress_src_port_range_id, range_id);
}

table ingress_l4_src_port {
    reads {
        l3_metadata.lkp_l4_sport : range;
    }
    actions {
        nop;
        set_ingress_src_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_ingress_dst_port_range_id(range_id) {
    modify_field(acl_metadata.ingress_dst_port_range_id, range_id);
}

table ingress_l4_dst_port {
    reads {
        l3_metadata.lkp_l4_dport : range;
    }
    actions {
        nop;
        set_ingress_dst_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}
#endif /* INGRESS_ACL_RANGE_DISABLE */

control process_ingress_l4port {
#ifndef INGRESS_ACL_RANGE_DISABLE
    apply(ingress_l4_src_port);
    apply(ingress_l4_dst_port);
#endif /* INGRESS_ACL_RANGE_DISABLE */
}

/*****************************************************************************/
/* ACL Actions                                                               */
/*****************************************************************************/
action acl_deny(acl_stats_index, acl_meter_index, acl_copy_reason,
                ingress_cos, tc, color, label) {
#ifdef ALT_INGRESS_DROP_ENABLE
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, DROP_ACL_DENY);
#else
    modify_field(acl_metadata.acl_deny, TRUE);
#endif /* ALT_INGRESS_DROP_ENABLE */
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#ifndef ACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* ACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef ACL_HIT_BIT_ENABLE
    modify_field(acl_metadata.acl_entry_hit, 1);
#endif /* ACL_HIT_BIT_ENABLE */
}

action acl_permit(acl_stats_index, acl_meter_index, acl_copy_reason,
                  nat_mode, ingress_cos, tc, color, label) {
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#ifndef ACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* ACL_REASON_CODE_DISABLE */
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef ACL_HIT_BIT_ENABLE
    modify_field(acl_metadata.acl_entry_hit, 1);
#endif /* ACL_HIT_BIT_ENABLE */
}

field_list i2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

field_list e2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

action acl_mirror(session_id, acl_stats_index, acl_meter_index, nat_mode,
                  ingress_cos, tc, color, label) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef ACL_HIT_BIT_ENABLE
    modify_field(acl_metadata.acl_entry_hit, 1);
#endif /* ACL_HIT_BIT_ENABLE */
}

action acl_redirect_nexthop(nexthop_index, acl_stats_index, acl_meter_index,
                            acl_copy_reason, nat_mode,
                            ingress_cos, tc, color, label) {
    modify_field(acl_metadata.acl_redirect, TRUE);
#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_SIMPLE);
#else
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#ifndef ACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* ACL_REASON_CODE_DISABLE */
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef ACL_HIT_BIT_ENABLE
    modify_field(acl_metadata.acl_entry_hit, 1);
#endif /* ACL_HIT_BIT_ENABLE */
}

action acl_redirect_ecmp(ecmp_index, acl_stats_index, acl_meter_index,
                         acl_copy_reason, nat_mode,
                         ingress_cos, tc, color, label) {
    modify_field(acl_metadata.acl_redirect, TRUE);
#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
    modify_field(l3_metadata.nexthop_index, ecmp_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_ECMP);
#else
    modify_field(acl_metadata.acl_nexthop, ecmp_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_ECMP);
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#ifndef ACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* ACL_REASON_CODE_DISABLE */
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef ACL_HIT_BIT_ENABLE
    modify_field(acl_metadata.acl_entry_hit, 1);
#endif /* ACL_HIT_BIT_ENABLE */
}

action acl_set_qos_fields(tc, color, acl_meter_index) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(ig_intr_md_for_tm.packet_color, color);
#if defined(QOS_METERING_ENABLE)
    modify_field(meter_metadata.meter_index, acl_meter_index);
#endif /* QOS_METERING_ENABLE */
}

/*****************************************************************************/
/* MAC ACL                                                                   */
/*****************************************************************************/
#ifndef L2_DISABLE
table mac_acl {
    reads {
        INGRESS_MAC_ACL_KEY
#ifdef USER_ACL_DMAC_LABEL_ENABLE
        INGRESS_ACL_KEY_DMAC_LABEL : ternary;
#endif
#ifdef VLAN_PRI_IN_MAC_ACL_ENABLE
        INGRESS_ACL_KEY_PCP              : ternary;
#endif
#ifdef VLAN_CFI_IN_MAC_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_CFI : ternary;
#endif
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
#ifdef RACL_DISABLE
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#endif
#ifdef INGRESS_ACL_ACTION_MIRROR_ENABLE
#ifndef MIRROR_ACTION_IN_MAC_ACL_DISABLE
        acl_mirror;
#endif
#endif /* INGRESS_ACL_ACTION_MIRROR_ENABLE */
    }
    size : INGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_mac_acl {
#if !defined(L2_DISABLE) && !defined(INGRESS_MAC_ACL_DISABLE)
    if (DO_LOOKUP(ACL)) {
        apply(mac_acl);
    }
#endif /* L2_DISABLE */
}

/*****************************************************************************/
/* FCOE ACL                                                                  */
/*****************************************************************************/
#ifdef FCOE_ACL_ENABLE
table fcoe_acl {
    reads {
        INGRESS_FCOE_ACL_KEY
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
#ifdef RACL_DISABLE
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#endif
    }
    size : INGRESS_FCOE_ACL_TABLE_SIZE;
}

control process_fcoe_acl {
    if (DO_LOOKUP(ACL)) {
        apply(fcoe_acl);
    }
}
#endif

/*****************************************************************************/
/* TCP Flags                                                                 */
/*****************************************************************************/

#ifdef TCP_FLAGS_LOU_ENABLE

action set_tcp_flags(tcp_flags) {
    modify_field(l3_metadata.lkp_tcp_flags, tcp_flags);
}

// This table can be used to perform logical operation on tcp.flags
table tcp_flags_lou {
    reads {
        l3_metadata.lkp_tcp_flags : exact;
    }

    actions {
        nop;
        set_tcp_flags;
    }

    size : TCP_FLAGS_LOU_TABLE_SIZE;
}

#endif /* TCP_FLAGS_LOU_ENABLE */

/*****************************************************************************/
/* IPv4 ACL                                                                  */
/*****************************************************************************/
#ifndef IPV4_DISABLE

#ifdef ATCAM
action set_ipv4_acl_partition_index(partition_index) {
    modify_field(acl_metadata.acl_partition_index, partition_index);
}

table ip_acl_partition {
    reads {
        INGRESS_IPV4_ACL_KEY
#ifdef USER_ACL_FIB_LABEL_ENABLE
        INGRESS_ACL_KEY_FIB_LABEL : ternary;
#endif /* USER_ACL_FIB_LABEL_ENABLE */
#ifdef STP_STATE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_STP_STATE : ternary;
#endif
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_ETYPE : ternary;
#endif
#ifdef DSCP_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_DSCP : ternary;
#endif /* DSCP_IN_IP_ACL_KEY_ENABLE */
#ifdef RACL_DISABLE
        INGRESS_ACL_KEY_RMAC_HIT : ternary;
#endif
#ifdef IPV4_FRAG_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_FRAG : ternary;
#endif
    }
    actions {
        set_ipv4_acl_partition_index;
    }
    size : IPV4_ACL_PARTITION_TABLE_SIZE;
}
#endif /* ATCAM */

#ifdef ATCAM
@pragma atcam_number_partitions IPV4_ACL_PARTITION_TABLE_SIZE
@pragma atcam_partition_index acl_metadata.acl_partition_index
@pragma ways 5
#endif /* ATCAM */
#ifdef L3_HEAVY_INT_LEAF_PROFILE
@pragma stage 5
#endif
table ip_acl {
    reads {
#ifdef ATCAM
        acl_metadata.acl_partition_index : exact;
#endif /* ATCAM */
        INGRESS_IPV4_ACL_KEY
#ifdef USER_ACL_FIB_LABEL_ENABLE
        INGRESS_ACL_KEY_FIB_LABEL : ternary;
#endif /* USER_ACL_FIB_LABEL_ENABLE */
#ifdef STP_STATE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_STP_STATE : ternary;
#endif
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_ETYPE : ternary;
#endif
#ifdef DSCP_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_DSCP : ternary;
#endif /* DSCP_IN_IP_ACL_KEY_ENABLE */
#ifdef RACL_DISABLE
        INGRESS_ACL_KEY_RMAC_HIT : ternary;
#endif
#ifdef IPV4_FRAG_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_FRAG : ternary;
#endif
#ifdef IP_FLAGS_IN_IP_ACL_ENABLE
        ipv4.flags : ternary;
#endif
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
#ifdef RACL_DISABLE
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#endif
#ifdef INGRESS_ACL_ACTION_MIRROR_ENABLE
        acl_mirror;
#endif /* INGRESS_ACL_ACTION_MIRROR_ENABLE */
    }
    size : INGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */


/*****************************************************************************/
/* IPv6 ACL                                                                  */
/*****************************************************************************/
#ifndef IPV6_DISABLE

#ifdef ATCAM
action set_ipv6_acl_partition_index(partition_index) {
    modify_field(acl_metadata.acl_partition_index, partition_index);
}

table ipv6_acl_partition {
    reads {
        INGRESS_IPV6_ACL_KEY
#ifdef USER_ACL_FIB_LABEL_ENABLE
	    INGRESS_ACL_KEY_FIB_LABEL : ternary;
#endif /* USER_ACL_FIB_LABEL_ENABLE */
#ifdef STP_STATE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_STP_STATE : ternary;
#endif
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_ETYPE : ternary;
#endif
#ifdef DSCP_IN_IP_ACL_KEY_ENABLE
    INGRESS_ACL_KEY_IP_DSCP : ternary;
#endif /* DSCP_IN_IP_ACL_KEY_ENABLE */
    }
    actions {
        set_ipv6_acl_partition_index;
    }
    size : IPV6_ACL_PARTITION_TABLE_SIZE;
}

#endif /* ATCAM */

#ifdef ATCAM
@pragma atcam_number_partitions IPV6_ACL_PARTITION_TABLE_SIZE
@pragma atcam_partition_index acl_metadata.acl_partition_index
@pragma ways 5
#endif /* ATCAM */

action set_compress_flow_label(label) {
  modify_field(acl_metadata.compact_ipv6_flow_label, label);
}

table compress_ipv6_flow_label {
  reads {
    ipv6.flowLabel : exact;
  }
  actions {
    set_compress_flow_label;
  }
}

table ipv6_acl {
    reads {
#ifdef ATCAM
        acl_metadata.acl_partition_index : exact;
#endif /* ATCAM */
        INGRESS_IPV6_ACL_KEY
#ifdef USER_ACL_FIB_LABEL_ENABLE
        l3_metadata.fib_label : ternary;
#endif /* USER_ACL_FIB_LABEL_ENABLE */
#ifdef STP_STATE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_STP_STATE : ternary;
#endif
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_ETYPE : ternary;
#endif
#ifdef DSCP_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_DSCP : ternary;
#endif /* DSCP_IN_IP_ACL_KEY_ENABLE */
#ifdef RACL_DISABLE
        INGRESS_ACL_KEY_RMAC_HIT : ternary;
#endif
#ifdef IPV6_FLOWLABEL_IN_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IPV6_FLOWLABEL : ternary;
#endif
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
#ifdef RACL_DISABLE
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#endif
#ifdef INGRESS_ACL_ACTION_MIRROR_ENABLE
        acl_mirror;
#endif /* INGRESS_ACL_ACTION_MIRROR_ENABLE */
    }
    size : INGRESS_IPV6_ACL_TABLE_SIZE;
}
#endif /* IPV6_DISABLE */

/*****************************************************************************/
/* QoS ACLs                                                                  */
/*****************************************************************************/
#if defined(MAC_QOS_ACL_ENABLE)
table mac_qos_acl {
    reads {
#if defined(QOS_ACL_KEYS_ENABLE)
        INGRESS_MAC_QOS_ACL_KEY
#else
        INGRESS_MAC_MIRROR_ACL_KEY
#endif
    }
    actions {
        INGRESS_QOS_MAP_ACTIONS
    }
    size : INGRESS_MAC_QOS_ACL_TABLE_SIZE;
}
#endif /* MAC_QOS_ACL_ENABLE */

#if defined(IPV4_QOS_ACL_ENABLE)
table ipv4_qos_acl {
    reads {
#if defined(QOS_ACL_KEYS_ENABLE)
        INGRESS_IPV4_QOS_ACL_KEY
#else
        INGRESS_IPV4_MIRROR_ACL_KEY
#endif
#if defined(PCP_IN_IPV4_QOS_ACL_KEY_ENABLE)
        INGRESS_ACL_KEY_PCP              : ternary;
#endif
    }
    actions {
        INGRESS_QOS_MAP_ACTIONS
    }
    size : INGRESS_IPV4_QOS_ACL_TABLE_SIZE;
}
#endif /* IPV4_QOS_ACL_ENABLE */

#if defined(IPV6_QOS_ACL_ENABLE)
table ipv6_qos_acl {
    reads {
#if defined(QOS_ACL_KEYS_ENABLE)
        INGRESS_IPV6_QOS_ACL_KEY
#else
        INGRESS_IPV6_MIRROR_ACL_KEY
#endif
#if defined(PCP_IN_IPV6_QOS_ACL_KEY_ENABLE)
        INGRESS_ACL_KEY_PCP              : ternary;
#endif
    }
    actions {
        INGRESS_QOS_MAP_ACTIONS
    }
    size : INGRESS_IPV6_QOS_ACL_TABLE_SIZE;
}
#endif /* IPV6_QOS_ACL_ENABLE */

/*****************************************************************************/
/* ACL Control flow                                                          */
/*****************************************************************************/
control process_tcp_flags {
#ifdef TCP_FLAGS_LOU_ENABLE
    apply(tcp_flags_lou);
#endif
}

control process_ip_acl {
    if (DO_LOOKUP(ACL)) {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
#ifndef IPV4_DISABLE
#ifdef ATCAM
            apply(ip_acl_partition);
#endif /* ATCAM */
            apply(ip_acl);
#endif /* IPV4_DISABLE */
        } else {
            if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
#if !defined(IPV6_DISABLE) && !defined(IPV6_ACL_DISABLE)
#ifdef ATCAM
                apply(ipv6_acl_partition);
#endif /* ATCAM */
                apply(ipv6_acl);
#endif /* IPV6_DISABLE */
            }
        }
    }
}

/*****************************************************************************/
/* RACL actions                                                              */
/*****************************************************************************/
action racl_deny(acl_stats_index, acl_copy_reason,
                 ingress_cos, tc, color, label) {
    modify_field(acl_metadata.racl_deny, TRUE);
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */

#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
#ifdef COLOR_ACTION_IN_RACL_ENABLE
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
}

action racl_permit(acl_stats_index, acl_copy_reason,
                   ingress_cos, tc, color, label, acl_meter_index, session_id) {
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
#ifdef COLOR_ACTION_IN_RACL_ENABLE
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef INGRESS_RACL_ACTION_MIRROR_ENABLE
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#endif
}

action racl_redirect_nexthop(nexthop_index, acl_stats_index,
                             acl_copy_reason,
                             ingress_cos, tc, color, label, acl_meter_index, session_id) {
    modify_field(acl_metadata.racl_redirect, TRUE);
#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
    modify_field(l3_metadata.nexthop_index, nexthop_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_SIMPLE);
#else
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
#ifdef COLOR_ACTION_IN_RACL_ENABLE
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef INGRESS_RACL_ACTION_MIRROR_ENABLE
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#endif
}

action racl_redirect_ecmp(ecmp_index, acl_stats_index,
                          acl_copy_reason,
                          ingress_cos, tc, color, label, acl_meter_index, session_id) {
    modify_field(acl_metadata.racl_redirect, TRUE);
#ifdef FWD_RESULTS_OPTIMIZATION_ENABLE
    modify_field(l3_metadata.nexthop_index, ecmp_index);
    modify_field(nexthop_metadata.nexthop_type, NEXTHOP_TYPE_ECMP);
#else
    modify_field(acl_metadata.acl_nexthop, ecmp_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_ECMP);
#endif /* FWD_RESULTS_OPTIMIZATION_ENABLE */
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
#ifdef ICOS_ACTION_IN_ACL_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
#endif
#ifdef TC_ACTION_IN_ACL_ENABLE
    modify_field(qos_metadata.lkp_tc, tc);
#endif
#ifdef COLOR_ACTION_IN_RACL_ENABLE
    modify_field(ig_intr_md_for_tm.packet_color, color);
#endif
#endif /* ACL_QOS_ENABLE */
#ifdef ACL_LABEL_ENABLE
    modify_field(acl_metadata.acl_label, label);
#endif /* ACL_LABEL_ENABLE */
#ifdef INGRESS_RACL_ACTION_MIRROR_ENABLE
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#endif
}


/*****************************************************************************/
/* IPv4 RACL                                                                 */
/*****************************************************************************/
#if !defined(IPV4_DISABLE) && !defined(RACL_DISABLE)
table ipv4_racl {
    reads {
        INGRESS_IPV4_ACL_KEY
#ifdef USER_ACL_FIB_LABEL_ENABLE
        INGRESS_ACL_KEY_FIB_LABEL : ternary;
#endif /* USER_ACL_FIB_LABEL_ENABLE */
#ifdef DSCP_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_DSCP : ternary;
#endif /* DSCP_IN_IP_ACL_KEY_ENABLE */
#ifdef IPV4_FRAG_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_FRAG : ternary;
#endif
#ifdef IP_FLAGS_IN_IP_ACL_ENABLE
        ipv4.flags : ternary;
#endif
    }
    actions {
        nop;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IP_RACL_TABLE_SIZE;
}
#endif /* !IPV4_DISABLE && !RACL_DISABLE */

control process_ipv4_racl {
#if !defined(IPV4_DISABLE) && !defined(RACL_DISABLE)
    apply(ipv4_racl);
#endif /* !IPV4_DISABLE && !RACL_DISABLE */
}

/*****************************************************************************/
/* IPv6 RACL                                                                 */
/*****************************************************************************/
#if !defined(IPV6_DISABLE) && !defined(RACL_DISABLE)
table ipv6_racl {
    reads {
        INGRESS_IPV6_ACL_KEY
#ifdef USER_ACL_FIB_LABEL_ENABLE
        INGRESS_ACL_KEY_FIB_LABEL : ternary;
#endif /* USER_ACL_FIB_LABEL_ENABLE */
#ifdef DSCP_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_DSCP : ternary;
#endif /* DSCP_IN_IP_ACL_KEY_ENABLE */
#ifdef IPV4_FRAG_IN_IP_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_FRAG : ternary;
#endif
#ifdef IPV6_FLOWLABEL_IN_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IPV6_FLOWLABEL : ternary;
#endif
    }
    actions {
        nop;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IPV6_RACL_TABLE_SIZE;
}
#endif /* !IPV6_DISABLE && !RACL_DISABLE */

control process_ipv6_racl {
#if !defined(IPV6_DISABLE) && !defined(RACL_DISABLE)
    apply(ipv6_racl);
#endif /* !IPV6_DISABLE && !RACL_DISABLE */
}

/*****************************************************************************/
/* Mirror ACL actions                                                        */
/*****************************************************************************/
action mirror_acl_mirror(session_id, acl_stats_index) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#ifdef MIRROR_ACL_STATS_ENABLE
    modify_field(acl_metadata.mirror_acl_stats_index, acl_stats_index);
#endif /* MIRROR_ACL_STATS_ENABLE */
}

/*****************************************************************************/
/* Ingress IPv4 Mirror ACL                                                   */
/*****************************************************************************/
#if !defined(IPV4_DISABLE) && defined(INGRESS_MIRROR_ACL_ENABLE)
table ipv4_mirror_acl {
    reads {
        INGRESS_IPV4_MIRROR_ACL_KEY
#ifdef ROCEV2_MIRROR_ENABLE
	    INGRESS_ACL_KEY_ROCEV2_OPCODE : ternary;
        INGRESS_ACL_KEY_ROCEV2_DST_QP_PLUS_RSVD : ternary;
        INGRESS_ACL_KEY_ROCEV2_AETH_SYNDROME : ternary;
#endif /* ROCEV2_MIRROR_ENABLE */
#ifdef ETYPE_IN_MIRROR_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_ETYPE : ternary;
#endif
    }
    actions {
        nop;
        mirror_acl_mirror;
    }
    size : MIRROR_ACL_TABLE_SIZE;
}
#endif /* !IPV4_DISABLE && INGRESS_MIRROR_ACL_ENABLE */

control process_ipv4_mirror_acl {
#if !defined(IPV4_DISABLE) && defined(INGRESS_MIRROR_ACL_ENABLE)
    apply(ipv4_mirror_acl);
#endif /* !IPV4_DISABLE && INGRESS_MIRROR_ACL_ENABLE */
}

/*****************************************************************************/
/* Ingress IPv6 Mirror ACL                                                   */
/*****************************************************************************/
#if !defined(IPV6_DISABLE) && defined(INGRESS_MIRROR_ACL_ENABLE)
table ipv6_mirror_acl {
    reads {
        INGRESS_IPV6_MIRROR_ACL_KEY
    }
    actions {
        nop;
        mirror_acl_mirror;
    }
    size : MIRROR_ACL_TABLE_SIZE;
}
#endif /* !IPV6_DISABLE && INGRESS_MIRROR_ACL_ENABLE */

control process_ipv6_mirror_acl {
#if !defined(IPV6_DISABLE) && defined(INGRESS_MIRROR_ACL_ENABLE)
    apply(ipv6_mirror_acl);
#endif /* !IPV6_DISABLE && INGRESS_MIRROR_ACL_ENABLE */
}

/*****************************************************************************/
/* DTEL ACL Prepare                                                          */
/*****************************************************************************/

#if defined(DTEL_ACL_ENABLE) && !defined(TUNNEL_PARSING_DISABLE)

action inner_outer_fields_outer_ethernet() {
    modify_field(acl_metadata.inner_outer_ip_type, IPTYPE_NONE);
    modify_field(acl_metadata.inner_outer_is_inner, 0);
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_etype, ethernet.etherType);
#endif
}

action inner_outer_fields_outer_ipv4() {
    modify_field(acl_metadata.inner_outer_ip_type, IPTYPE_IPV4);
    modify_field(acl_metadata.inner_outer_is_inner, 0);
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_etype, ethernet.etherType);
#endif /* ETYPE_IN_DTEL_ACL_KEY_ENABLE */
    modify_field(acl_metadata.inner_outer_ipv4_sa, ipv4.srcAddr);
    modify_field(acl_metadata.inner_outer_ipv4_da, ipv4.dstAddr);
    modify_field(acl_metadata.inner_outer_ip_proto, ipv4.protocol);
#ifdef DSCP_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_ip_dscp, ipv4.diffserv);
#endif /* DSCP_IN_DTEL_ACL_KEY_ENABLE */
#ifdef DTEL_ACL_RANGE_DISABLE
    modify_field(acl_metadata.inner_outer_ip_sport, l3_metadata.lkp_l4_sport);
    modify_field(acl_metadata.inner_outer_ip_dport, l3_metadata.lkp_l4_dport);
#endif /* DTEL_ACL_RANGE_DISABLE */
}

action inner_outer_fields_outer_ipv6() {
    modify_field(acl_metadata.inner_outer_ip_type, IPTYPE_IPV6);
    modify_field(acl_metadata.inner_outer_is_inner, 0);
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_etype, ethernet.etherType);
#endif /* ETYPE_IN_DTEL_ACL_KEY_ENABLE */
#ifndef DTEL_ACL_IPV6_DISABLE
    modify_field(acl_metadata.inner_outer_ipv6_sa, ipv6.srcAddr);
    modify_field(acl_metadata.inner_outer_ipv6_da, ipv6.dstAddr);
#endif /* !DTEL_ACL_IPV6_DISABLE */
#if !defined(DTEL_ACL_IPV6_DISABLE) || defined(ETYPE_IN_DTEL_ACL_KEY_ENABLE)
    modify_field(acl_metadata.inner_outer_ip_proto, ipv6.nextHdr);
#ifdef DSCP_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_ip_dscp, ipv6.trafficClass);
#endif /* DSCP_IN_DTEL_ACL_KEY_ENABLE */
#ifdef DTEL_ACL_RANGE_DISABLE
    modify_field(acl_metadata.inner_outer_ip_sport, l3_metadata.lkp_l4_sport);
    modify_field(acl_metadata.inner_outer_ip_dport, l3_metadata.lkp_l4_dport);
#endif /* DTEL_ACL_RANGE_DISABLE */
#endif /* !DTEL_ACL_IPV6_DISABLE || ETYPE_IN_DTEL_ACL_KEY_ENABLE */
}

action inner_outer_fields_inner_ethernet() {
    modify_field(acl_metadata.inner_outer_ip_type, IPTYPE_NONE);
    modify_field(acl_metadata.inner_outer_is_inner, 1);
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_etype, inner_ethernet.etherType);
#endif
}

action inner_outer_fields_inner_ipv4() {
    modify_field(acl_metadata.inner_outer_ip_type, IPTYPE_IPV4);
    modify_field(acl_metadata.inner_outer_is_inner, 1);
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_etype, ETHERTYPE_IPV4);
#endif /* ETYPE_IN_DTEL_ACL_KEY_ENABLE */
    modify_field(acl_metadata.inner_outer_ipv4_sa, inner_ipv4.srcAddr);
    modify_field(acl_metadata.inner_outer_ipv4_da, inner_ipv4.dstAddr);
    modify_field(acl_metadata.inner_outer_ip_proto, inner_ipv4.protocol);
#ifdef DSCP_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_ip_dscp, inner_ipv4.diffserv);
#endif /* DSCP_IN_DTEL_ACL_KEY_ENABLE */
#ifdef DTEL_ACL_RANGE_DISABLE
    modify_field(acl_metadata.inner_outer_ip_sport,
                 l3_metadata.lkp_inner_l4_sport);
    modify_field(acl_metadata.inner_outer_ip_dport,
                 l3_metadata.lkp_inner_l4_dport);
#endif /* DTEL_ACL_RANGE_DISABLE */
}

action inner_outer_fields_inner_ipv6() {
    modify_field(acl_metadata.inner_outer_ip_type, IPTYPE_IPV6);
    modify_field(acl_metadata.inner_outer_is_inner, 1);
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_etype, ETHERTYPE_IPV6);
#endif /* ETYPE_IN_DTEL_ACL_KEY_ENABLE */
#ifndef DTEL_ACL_IPV6_DISABLE
    modify_field(acl_metadata.inner_outer_ipv6_sa, inner_ipv6.srcAddr);
    modify_field(acl_metadata.inner_outer_ipv6_da, inner_ipv6.dstAddr);
#endif /* !DTEL_ACL_IPV6_DISABLE */
#if !defined(DTEL_ACL_IPV6_DISABLE) || defined(ETYPE_IN_DTEL_ACL_KEY_ENABLE)
    modify_field(acl_metadata.inner_outer_ip_proto, inner_ipv6.nextHdr);
#ifdef DSCP_IN_DTEL_ACL_KEY_ENABLE
    modify_field(acl_metadata.inner_outer_ip_dscp, inner_ipv6.trafficClass);
#endif /* DSCP_IN_DTEL_ACL_KEY_ENABLE */
#ifdef DTEL_ACL_RANGE_DISABLE
    modify_field(acl_metadata.inner_outer_ip_sport,
                 l3_metadata.lkp_inner_l4_sport);
    modify_field(acl_metadata.inner_outer_ip_dport,
                 l3_metadata.lkp_inner_l4_dport);
#endif /* DTEL_ACL_RANGE_DISABLE */
#endif /* !DTEL_ACL_IPV6_DISABLE || ETYPE_IN_DTEL_ACL_KEY_ENABLE */
}

table dtel_acl_prepare {
    reads {
        ipv4                         : valid;
        ipv6                         : valid;
#if defined(GRE_INNER_IP_HASHING_ENABLE) || defined(INNER_HASHING_ENABLE)
        inner_ethernet               : valid;
        inner_ipv4                   : valid;
        inner_ipv6                   : valid;
#ifdef GRE_INNER_IP_HASHING_ENABLE
        gre                          : valid;
#endif
#endif
    }
    actions {
        nop;
        inner_outer_fields_outer_ethernet;
        inner_outer_fields_outer_ipv4;
        inner_outer_fields_outer_ipv6;
        inner_outer_fields_inner_ethernet;
        inner_outer_fields_inner_ipv4;
        inner_outer_fields_inner_ipv6;
    }
    size: 32;
}

#ifndef DTEL_ACL_RANGE_DISABLE
action set_inner_src_port_range_id(range_id) {
    modify_field(acl_metadata.inner_outer_src_port_range_id, range_id);
}

table ingress_inner_l4_src_port {
    reads {
        l3_metadata.lkp_inner_l4_sport : range;
    }
    actions {
        nop;
        set_inner_src_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_inner_dst_port_range_id(range_id) {
    modify_field(acl_metadata.inner_outer_dst_port_range_id, range_id);
}

table ingress_inner_l4_dst_port {
    reads {
        l3_metadata.lkp_inner_l4_dport : range;
    }
    actions {
        nop;
        set_inner_dst_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}

action copy_outer_l4_port_ranges() {
    modify_field(acl_metadata.inner_outer_src_port_range_id,
                 acl_metadata.ingress_src_port_range_id);
    modify_field(acl_metadata.inner_outer_dst_port_range_id,
                 acl_metadata.ingress_dst_port_range_id);
}

table ingress_copy_outer_l4_port_ranges {
    actions {
        copy_outer_l4_port_ranges;
    }
    default_action: copy_outer_l4_port_ranges;
    size : 1;
}
#endif /* !DTEL_ACL_RANGE_DISABLE */

#endif /* DTEL_ACL_ENABLE && !TUNNEL_PARSING_DISABLE */

/*****************************************************************************/
/* DTEL ACL actions                                                          */
/*****************************************************************************/

#if defined(DTEL_ACL_ENABLE)

action dtel_acl_watch_flow(suppress_enb, config_session_id, sample_index,
                           acl_stats_index) {
#ifdef POSTCARD_ENABLE
    postcard_watch_sample(suppress_enb, sample_index);
#elif defined(INT_EP_ENABLE)
    int_watch_sample(suppress_enb, config_session_id, sample_index);
#endif /* POSTCARD_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

action dtel_acl_watch_drop_dod(suppress_enb, acl_stats_index) {
#ifdef DTEL_DROP_REPORT_ENABLE
    mod_watch_dod(suppress_enb);
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

action dtel_acl_watch_drop_no_dod(suppress_enb, acl_stats_index) {
#ifdef DTEL_DROP_REPORT_ENABLE
    mod_watch_nodod(0x1, suppress_enb);
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

action dtel_acl_watch_flow_drop_dod(suppress_enb, config_session_id,
                                    sample_index, acl_stats_index) {
#ifdef POSTCARD_ENABLE
    postcard_watch_sample(suppress_enb, sample_index);
#elif defined(INT_EP_ENABLE)
    int_watch_sample(suppress_enb, config_session_id, sample_index);
#endif /* POSTCARD_ENABLE */
#ifdef DTEL_DROP_REPORT_ENABLE
    mod_watch_dod(suppress_enb);
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

action dtel_acl_watch_flow_drop_no_dod(suppress_enb, config_session_id,
                                       sample_index, acl_stats_index) {
#ifdef POSTCARD_ENABLE
    postcard_watch_sample(suppress_enb, sample_index);
#elif defined(INT_EP_ENABLE)
    int_watch_sample(suppress_enb, config_session_id, sample_index);
#endif /* POSTCARD_ENABLE */
#ifdef DTEL_DROP_REPORT_ENABLE
    mod_watch_nodod(0x1, suppress_enb);
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

#ifdef DTEL_ACL_SEPARATE_STAGES
action dtel_acl_watch_flow_v6(suppress_enb, config_session_id, sample_index,
                              acl_stats_index) {
#ifdef POSTCARD_ENABLE
    postcard_watch_sample_v6(suppress_enb, sample_index);
#elif defined(INT_EP_ENABLE)
    int_watch_sample(suppress_enb, config_session_id, sample_index);
#endif /* POSTCARD_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

action dtel_acl_watch_flow_drop_dod_v6(suppress_enb, config_session_id,
                                       sample_index, acl_stats_index) {
#ifdef POSTCARD_ENABLE
    postcard_watch_sample_v6(suppress_enb, sample_index);
#elif defined(INT_EP_ENABLE)
    int_watch_sample(suppress_enb, config_session_id, sample_index);
#endif /* POSTCARD_ENABLE */
#ifdef DTEL_DROP_REPORT_ENABLE
    mod_watch_dod(suppress_enb);
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

action dtel_acl_watch_flow_drop_no_dod_v6(suppress_enb, config_session_id,
                                          sample_index, acl_stats_index) {
#ifdef POSTCARD_ENABLE
    postcard_watch_sample_v6(suppress_enb, sample_index);
#elif defined(INT_EP_ENABLE)
    int_watch_sample(suppress_enb, config_session_id, sample_index);
#endif /* POSTCARD_ENABLE */
#ifdef DTEL_DROP_REPORT_ENABLE
    mod_watch_nodod(0x1, suppress_enb);
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}
#endif /* DTEL_ACL_SEPARATE_STAGES */

action dtel_acl_mirror(session_id, acl_stats_index) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#ifdef DTEL_ACL_STATS_ENABLE
    modify_field(acl_metadata.dtel_acl_stats_index, acl_stats_index);
#endif /* DTEL_ACL_STATS_ENABLE */
}

#endif /* DTEL_ACL_ENABLE */

/*****************************************************************************/
/* IPv4 DTEL ACL                                                             */
/*****************************************************************************/
#if !defined(IPV4_DISABLE) && defined(DTEL_ACL_ENABLE)
#if defined(Q0_PROFILE)
@pragma stage 9
#endif
table ipv4_dtel_acl {
    reads {
        INGRESS_IPV4_DTEL_ACL_KEY
#ifdef DSCP_IN_DTEL_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_I_O_IP_DSCP         : ternary;
#endif
#ifdef DTEL_ACL_RANGE_DISABLE
        INGRESS_ACL_KEY_I_O_L4_SRC_PORT     : ternary;
        INGRESS_ACL_KEY_I_O_L4_DST_PORT     : ternary;
#else
        INGRESS_ACL_KEY_I_O_SRC_PORT_RANGE  : ternary;
        INGRESS_ACL_KEY_I_O_DST_PORT_RANGE  : ternary;
#endif
#ifdef ETYPE_IN_DTEL_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_I_O_ETYPE           : ternary;
#endif
#ifdef INT_EP_ENABLE
        int_metadata.sink                   : ternary;
#ifdef INT_OVER_L4_ENABLE
        int_metadata.postcard_mode          : ternary;
        tcp.valid                           : ternary;
        udp.valid                           : ternary;
        icmp.valid                          : ternary;
        ipv4.ihl                            : ternary;
#endif /* INT_OVER_L4_ENABLE */
#endif /* INT_EP_ENABLE */
    }
    actions {
        nop;
        dtel_acl_watch_flow;
        dtel_acl_watch_drop_dod;
        dtel_acl_watch_drop_no_dod;
        dtel_acl_watch_flow_drop_dod;
        dtel_acl_watch_flow_drop_no_dod;
#ifdef DTEL_ACL_ACTION_MIRROR_ENABLE
        dtel_acl_mirror;
#endif /* DTEL_ACL_ACTION_MIRROR_ENABLE */
    }
    size : DTEL_ACL_TABLE_SIZE;
}
#endif /* !IPV4_DISABLE && DTEL_ACL_ENABLE */

/*****************************************************************************/
/* IPv6 DTEL ACL                                                             */
/*****************************************************************************/
#if !defined(IPV6_DISABLE) && defined(DTEL_ACL_ENABLE) && \
    !defined(DTEL_ACL_IPV6_DISABLE)
table ipv6_dtel_acl {
    reads {
        INGRESS_IPV6_DTEL_ACL_KEY
#ifdef DSCP_IN_DTEL_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_I_O_IP_DSCP         : ternary;
#endif
#if defined(DTEL_ACL_RANGE_DISABLE)
        INGRESS_ACL_KEY_I_O_L4_SRC_PORT     : ternary;
        INGRESS_ACL_KEY_I_O_L4_DST_PORT     : ternary;
#else
        INGRESS_ACL_KEY_I_O_SRC_PORT_RANGE  : ternary;
        INGRESS_ACL_KEY_I_O_DST_PORT_RANGE  : ternary;
#endif
#ifdef INT_EP_ENABLE
        int_metadata.sink                   : ternary;
#ifdef INT_OVER_L4_ENABLE
        int_metadata.postcard_mode          : ternary;
        tcp.valid                           : ternary;
        udp.valid                           : ternary;
        icmp.valid                          : ternary;
#endif /* INT_OVER_L4_ENABLE */
#endif
    }
    actions {
        nop;
        dtel_acl_watch_drop_dod;
        dtel_acl_watch_drop_no_dod;
#ifdef DTEL_ACL_SEPARATE_STAGES
        dtel_acl_watch_flow_v6;
        dtel_acl_watch_flow_drop_dod_v6;
        dtel_acl_watch_flow_drop_no_dod_v6;
#else
        dtel_acl_watch_flow;
        dtel_acl_watch_flow_drop_dod;
        dtel_acl_watch_flow_drop_no_dod;
#endif /* DTEL_ACL_SEPARATE_STAGES */
#ifdef DTEL_ACL_ACTION_MIRROR_ENABLE
        dtel_acl_mirror;
#endif /* DTEL_ACL_ACTION_MIRROR_ENABLE */
    }
    size : DTEL_ACL_TABLE_SIZE;
}
#endif /* !IPV6_DISABLE && DTEL_ACL_ENABLE && !DTEL_ACL_IPV6_DISABLE */

/*****************************************************************************/
/* DTEL ACL Control                                                          */
/*****************************************************************************/
control process_dtel_acl {
#ifdef DTEL_ACL_ENABLE
#if !defined(TUNNEL_PARSING_DISABLE)
    apply(dtel_acl_prepare);

#ifndef DTEL_ACL_RANGE_DISABLE
    if (valid(inner_ipv4) or valid(inner_ipv6)) {
        apply(ingress_inner_l4_src_port);
        apply(ingress_inner_l4_dst_port);
#if !defined(Q0_PROFILE)
    } else {
        apply(ingress_copy_outer_l4_port_ranges);
#endif
    }
#endif /* DTEL_ACL_RANGE_DISABLE */
#endif /* !TUNNEL_PARSING_DISABLE */

#if !defined(IPV6_DISABLE) && !defined(DTEL_ACL_IPV6_DISABLE)
    if (acl_metadata.inner_outer_ip_type == IPTYPE_IPV6) {
        apply(ipv6_dtel_acl);
    }
#if !defined(IPV4_DISABLE)
    else
#endif /* !IPV4_DISABLE */
#endif /* !IPV6_DISABLE && !DTEL_ACL_IPV6_DISABLE */
#if !defined(IPV4_DISABLE)
#ifndef ETYPE_IN_DTEL_ACL_KEY_ENABLE
    if (acl_metadata.inner_outer_ip_type == IPTYPE_IPV4)
#endif /* !ETYPE_IN_DTEL_ACL_KEY_ENABLE */
// #if (!defined(IPV6_DISABLE) && !defined(DTEL_ACL_IPV6_DISABLE)) || !defined(ETYPE_IN_DTEL_ACL_KEY_ENABLE)
    {
// #endif
        apply(ipv4_dtel_acl);
// #if (!defined(IPV6_DISABLE) && !defined(DTEL_ACL_IPV6_DISABLE)) || !defined(ETYPE_IN_DTEL_ACL_KEY_ENABLE)
    }
// #endif
#endif /* !IPV4_DISABLE */

#endif /* DTEL_ACL_ENABLE */
}

/*****************************************************************************/
/* ACL stats                                                                 */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter acl_stats {
    type : packets_and_bytes;
    instance_count : ACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action acl_stats_update() {
    count(acl_stats, acl_metadata.acl_stats_index);
}

table acl_stats {
    actions {
        acl_stats_update;
    }
    default_action : acl_stats_update;
    size : ACL_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

#ifdef MIRROR_ACL_STATS_ENABLE
counter mirror_acl_stats {
 type : packets_and_bytes;
 instance_count : MIRROR_ACL_STATS_TABLE_SIZE;
 min_width : 16;
}

action mirror_acl_stats_update() {
  count(mirror_acl_stats, acl_metadata.mirror_acl_stats_index);
}

table mirror_acl_stats {
  actions {
    mirror_acl_stats_update;
  }
  default_action : mirror_acl_stats_update;
 size : MIRROR_ACL_STATS_TABLE_SIZE;
}
#endif /* MIRROR_ACL_STATS_ENABLE */

#ifdef RACL_STATS_ENABLE
counter racl_stats {
    type : packets_and_bytes;
    instance_count : RACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action racl_stats_update() {
    count(racl_stats, acl_metadata.racl_stats_index);
}

table racl_stats {
    actions {
        racl_stats_update;
    }
    default_action : racl_stats_update;
    size : RACL_STATS_TABLE_SIZE;
}
#endif /* RACL_STATS_ENABLE */

#if defined(MAC_QOS_ACL_ENABLE)
counter mac_qos_acl_stats {
    type : packets_and_bytes;
    direct : mac_qos_acl;
    min_width : 32;
}
#endif /* MAC_QOS_ACL_ENABLE */

#if defined(IPV4_QOS_ACL_ENABLE)
counter ipv4_qos_acl_stats {
    type : packets_and_bytes;
    direct : ipv4_qos_acl;
    min_width : 32;
}
#endif /* IPV4_QOS_ACL_ENABLE */

#if defined(IPV6_QOS_ACL_ENABLE)
counter ipv6_qos_acl_stats {
    type : packets_and_bytes;
    direct : ipv6_qos_acl;
    min_width : 32;
}
#endif /* IPV6_QOS_ACL_ENABLE */

control process_ingress_acl_stats {
#ifndef STATS_DISABLE
    apply(acl_stats);
#endif /* STATS_DISABLE */
}

control process_ingress_mirror_acl_stats {
#ifdef MIRROR_ACL_STATS_ENABLE
  apply(mirror_acl_stats);
#endif /* MIRROR_ACL_STATS_ENABLE */
}

control process_ingress_racl_stats {
#ifdef RACL_STATS_ENABLE
    apply(racl_stats);
#endif /* RACL_STATS_ENABLE */
}

/*****************************************************************************/
/* CoPP                                                                      */
/*****************************************************************************/
#ifndef COPP_METER_DISABLE
meter copp {
    type: packets;
    static: system_acl;
    result: ig_intr_md_for_tm.packet_color;
    instance_count: COPP_TABLE_SIZE;
}
#endif /* !COPP_METER_DISABLE */

#ifdef COPY_TO_CPU_USING_RECIRC
meter cpu_copy_copp {
    type: packets;
    static: recirc_port_copy_to_cpu;
    result: ig_intr_md_for_tm.packet_color;
    instance_count: COPP_TABLE_SIZE;
}

action set_cpu_queue_id(qid, cpu_port, meter_id) {
  modify_field(ig_intr_md_for_tm.qid, qid);
  modify_field(ig_intr_md_for_tm.ucast_egress_port, cpu_port);
  execute_meter(cpu_copy_copp, meter_id, ig_intr_md_for_tm.packet_color);
  modify_field(acl_metadata.copp_meter_id, meter_id);
  modify_field(ig_intr_md_for_tm.mcast_grp_b, 0);
}

table recirc_port_copy_to_cpu {
  reads {
    fabric_header_cpu.reasonCode:exact;
  }
  actions {
    set_cpu_queue_id;
  }
}
#endif

#ifdef INGRESS_COPP_ENABLE
counter copp_stats {
    type   : packets;
    direct : copp_drop;
}

action copp_drop() {
#ifdef COPY_TO_CPU_USING_RECIRC
  drop();
#else
  modify_field(ig_intr_md_for_tm.copy_to_cpu, 0);
  modify_field(ig_intr_md_for_tm.ucast_egress_port, INVALID_PORT_ID);
#endif
}

table copp_drop {
    reads {
        ig_intr_md_for_tm.packet_color : ternary;
        acl_metadata.copp_meter_id : ternary;
    }
    actions {
        nop;
        copp_drop;
#ifdef ALT_SYSTEM_ACL_ENABLE
        on_miss;
#endif
    }
    size : COPP_DROP_TABLE_SIZE;
}
#endif /* INGRESS_COPP_ENABLE */

/*****************************************************************************/
/* System ACL                                                                */
/*****************************************************************************/
counter drop_stats {
    type : packets;
    instance_count : DROP_STATS_TABLE_SIZE;
}

counter drop_stats_2 {
    type : packets;
    instance_count : DROP_STATS_TABLE_SIZE;
}

#ifdef LEARN_INVALIDATE_ENABLE
action invalidate_learn_digest() {
  invalidate_digest();
}

#ifdef DTEL_DROP_REPORT_ENABLE
action mirror_and_drop_and_learn_inv() {
    mirror_and_drop();
    invalidate_learn_digest();
}

action mirror_and_drop_with_reason_and_learn_inv(drop_reason) {
    mirror_and_drop_with_reason(drop_reason);
    invalidate_learn_digest();
}
#endif /* DTEL_DROP_REPORT_ENABLE */
 
action redirect_to_cpu_and_learn_inv(qid, meter_id, icos,cpu_port) {
    redirect_to_cpu(qid, meter_id, icos,cpu_port);
    invalidate_learn_digest();
}

action redirect_to_cpu_with_reason_and_learn_inv(reason_code, qid, meter_id, icos,cpu_port) {
    redirect_to_cpu_with_reason(reason_code, qid, meter_id, icos,cpu_port);
    invalidate_learn_digest();
}

action copy_to_cpu_and_learn_inv(qid, meter_id, icos) {
    copy_to_cpu(qid, meter_id, icos);
    invalidate_learn_digest();
}

action copy_to_cpu_with_reason_and_learn_inv(reason_code, qid, meter_id, icos) {
    copy_to_cpu_with_reason(reason_code, qid, meter_id, icos);
    invalidate_learn_digest();
}

action drop_packet_and_learn_inv() {
    drop_packet();
    invalidate_learn_digest();
}

action drop_packet_with_reason_and_learn_inv(drop_reason) {
    drop_packet_with_reason(drop_reason);
    invalidate_learn_digest();
}
#endif /* LEARN_INVALIDATE_ENABLE */

#ifdef DTEL_DROP_REPORT_ENABLE
field_list i2e_mirror_and_drop_info {
    ingress_metadata.drop_reason;
    i2e_metadata.mirror_session_id;
    i2e_metadata.ingress_tstamp;
    ingress_metadata.ingress_port;
    dtel_md.mod_watchlist_hit;
    egress_metadata.egress_port;
    dtel_md.flow_hash;
#ifdef INT_EP_ENABLE
    int_metadata.source;
    int_metadata.sink;
#endif // INT_EP_ENABLE
#ifdef INT_TRANSIT_ENABLE
    int_metadata.path_tracking_flow;
#endif // INT_TRANSIT_ENABLE
#ifdef POSTCARD_ENABLE
    postcard_md.report;
#endif // POSTCARD_ENABLE;
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    dtel_md.drop_flow_suppress;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}

action mirror_and_drop() {
    modify_field(i2e_metadata.mirror_session_id,
                 dtel_md.mirror_session_id);
    modify_field(egress_metadata.egress_port, INVALID_PORT_ID);
    clone_ingress_pkt_to_egress(dtel_md.mirror_session_id,
                                i2e_mirror_and_drop_info);
    drop();
}

action mirror_and_drop_with_reason(drop_reason) {
    count(drop_stats, drop_reason);
    modify_field(ingress_metadata.drop_reason, drop_reason);
    modify_field(acl_metadata.acl_deny, FALSE);
    mirror_and_drop();
}
#endif /* DTEL_DROP_REPORT_ENABLE */

action redirect_to_cpu_with_reason(reason_code, qid, meter_id, icos,cpu_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, cpu_port);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(fabric_metadata.reason_code, reason_code);
#ifndef COPP_METER_DISABLE
    execute_meter(copp, meter_id, ig_intr_md_for_tm.packet_color);
    modify_field(acl_metadata.copp_meter_id, meter_id);
#endif /* COPP_METER_DISABLE */
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action redirect_to_port(dst_port) {
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
    modify_field(ig_intr_md_for_tm.ucast_egress_port, dst_port);
}

action redirect_to_cpu(qid, meter_id, icos, cpu_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, cpu_port);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
#ifndef COPP_METER_DISABLE
    execute_meter(copp, meter_id, ig_intr_md_for_tm.packet_color);
    modify_field(acl_metadata.copp_meter_id, meter_id);
#endif /* COPP_METER_DISABLE */
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

field_list cpu_info {
    ingress_metadata.bd;
    ingress_metadata.ifindex;
    fabric_metadata.reason_code;
    ingress_metadata.ingress_port;
}

action copy_to_cpu(qid, meter_id, icos) {
#ifndef COPY_TO_CPU_USING_RECIRC
    modify_field(ig_intr_md_for_tm.qid, qid);
#endif
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
#ifdef __TARGET_TOFINO__
    modify_field(ig_intr_md_for_tm.copy_to_cpu, TRUE);
#else
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
#endif
#ifndef COPP_METER_DISABLE
#ifndef COPY_TO_CPU_USING_RECIRC
    execute_meter(copp, meter_id, ig_intr_md_for_tm.packet_color);
    modify_field(acl_metadata.copp_meter_id, meter_id);
#endif
#endif /* COPP_METER_DISABLE */
}

action copy_to_cpu_with_reason(reason_code, qid, meter_id, icos) {
    modify_field(fabric_metadata.reason_code, reason_code);
    copy_to_cpu(qid, meter_id, icos);
}

action drop_packet() {
    drop();
}

action drop_packet_with_reason(drop_reason) {
#ifdef PORT_DROP_STATS_ENABLE
    modify_field(ingress_metadata.drop_reason, drop_reason);
#endif /* PORT_DROP_STATS_ENABLE */
    count(drop_stats, drop_reason);
    drop();
}

action drop_cancel() {
  modify_field(ig_intr_md_for_tm.drop_ctl,DROP_CTL_FORWARD_BIT,1);
}

#ifdef SYSTEM_LOW_PRI_ACL_ENABLE
meter copp2 {
    type: packets;
    static: system_acl_2;
    result: ig_intr_md_for_tm.packet_color;
    instance_count: COPP_TABLE_SIZE;
}
counter copp_stats_2 {
    type   : packets;
    direct : copp_drop_2;
}

action copp_drop_2() {
#ifdef COPY_TO_CPU_USING_RECIRC
  drop();
#else
  modify_field(ig_intr_md_for_tm.copy_to_cpu, 0);
  modify_field(ig_intr_md_for_tm.ucast_egress_port, INVALID_PORT_ID);
#endif
}

table copp_drop_2 {
    reads {
        ig_intr_md_for_tm.packet_color : exact;
        acl_metadata.copp_meter_id_2 : exact;
    }
    actions {
        nop;
        copp_drop_2;
    }
    size : COPP_DROP_TABLE_SIZE;
}
action redirect_to_cpu_with_reason_2(reason_code, qid, meter_id, icos, cpu_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, cpu_port);
    modify_field(fabric_metadata.reason_code, reason_code);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(acl_metadata.copp_meter_id_2, meter_id);
    execute_meter(copp2, meter_id, ig_intr_md_for_tm.packet_color);
}

action drop_packet_with_reason_2(meter_id) {
    modify_field(acl_metadata.copp_meter_id_2, meter_id);
    drop();
}


action copy_to_cpu_with_reason_2(reason_code, qid, meter_id, icos) {
    modify_field(fabric_metadata.reason_code, reason_code);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(acl_metadata.copp_meter_id_2, meter_id);
#ifdef __TARGET_TOFINO__
    modify_field(ig_intr_md_for_tm.copy_to_cpu, TRUE);
#else
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
#endif
    execute_meter(copp2, meter_id, ig_intr_md_for_tm.packet_color);
}

action set_drop_reason(drop_reason) {
  modify_field(ingress_metadata.drop_reason, drop_reason);
}

counter system_reason_acl_stats {
    type : packets_and_bytes;
    direct : system_reason_acl;
    min_width : 32;
}

table system_reason_acl {
  reads {
    INGRESS_ACL_KEY_VLAN_MBR_CHECK_FAIL : ternary; \
    acl_metadata.acl_deny : ternary; \
    meter_metadata.meter_drop : ternary; \
    meter_metadata.storm_control_color : ternary; \
    l3_metadata.routed : ternary; \
    l3_metadata.same_bd_check : ternary; \
    l2_metadata.same_if_check : ternary;
  }
  actions {
    set_drop_reason;
  } 
  size : SYSTEM_ACL_SIZE;
}

table system_acl_2 {
  reads {
        INGRESS_SYSTEM_ACL_2_KEY
  }
  actions {
        nop;
        redirect_to_cpu_with_reason_2;
        copy_to_cpu_with_reason_2;
        drop_packet_with_reason_2;
        redirect_to_port;
        drop_cancel;
  }
  size : SYSTEM_ACL_SIZE;
}

#endif /* SYSTEM_LOW_PRI_ACL_ENABLE */

counter color_action_stats {
  type : packets;
  direct : color_action;
  min_width : 16;
}

table color_action {
  reads {
    INGRESS_ACL_KEY_PACKET_COLOR : ternary;
    acl_metadata.acl_label : ternary;
  }
  actions {
    nop;
    drop_packet;
  }
}
    
#if defined(M0_PROFILE)
@pragma stage 10
#endif
table system_acl {
    reads {
#ifdef SYSTEM_FLOW_ACL_ENABLE
        INGRESS_SYSTEM_FLOW_KEY
#elif defined(Q0_PROFILE)
        Q_PROFILES_INGRESS_SYSTEM_ACL_KEY
#else
#if defined(PORT_IN_SYSTEM_ACL_KEY_ENABLE)
        INGRESS_ACL_KEY_PORT_LABEL : ternary;
#endif

#ifdef BD_LABEL_IN_SYSTEM_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_BD_LABEL : ternary;
#endif
#ifdef INGRESS_IFINDEX_IN_SYSTEM_ACL_KEY_ENABLE
        ingress_metadata.ifindex : ternary;
#endif
        // should we add port_lag_index here?

        /* drop reasons */
        l2_metadata.lkp_mac_type : ternary;
        l2_metadata.port_vlan_mapping_miss : ternary;
        l2_metadata.ingress_vlan_mbr_check_fail : ternary;
#ifndef IPSG_DISABLE
        security_metadata.ipsg_check_fail : ternary;
#endif /* !IPSG_DISABLE */
        acl_metadata.acl_deny : ternary;
#ifndef RACL_DISABLE
        acl_metadata.racl_deny: ternary;
#endif /* RACL_DISABLE */
#if !defined(URPF_DISABLE)
        l3_metadata.urpf_check_fail : ternary;
#endif /* !URPF_DISABLE */
#if !defined(STORM_CONTROL_DISABLE)
        meter_metadata.storm_control_color : ternary;
#endif /* !STORM_CONTROL_DISABLE */
#if defined(QOS_METERING_ENABLE)
        meter_metadata.meter_drop : ternary;
#endif /* QOS_METERING_ENABLE */
        ingress_metadata.drop_flag : ternary;

        l3_metadata.rmac_hit : ternary;
        l3_metadata.fib_hit_myip : ternary;
#if !defined(NEXTHOP_GLEAN_OPTIMIZATION_ENABLE)
        nexthop_metadata.nexthop_glean : ternary;
#endif /* NEXTHOP_GLEAN_OPTIMIZATIONE_ENABLE */

        /*
         * other checks, routed link_local packet, l3 same if check,
         * expired ttl
         */
#if !defined(L3_MULTICAST_DISABLE)
        l3_metadata.l3_copy : ternary;

        multicast_metadata.mcast_route_hit : ternary;
        multicast_metadata.mcast_route_s_g_hit : ternary;
        multicast_metadata.mcast_copy_to_cpu : ternary;
        multicast_metadata.mcast_rpf_fail : ternary;
        multicast_metadata.ipv4_multicast_enabled : ternary;
        multicast_metadata.igmp_snooping_enabled : ternary;
#ifndef IPV6_DISABLE
        multicast_metadata.ipv6_multicast_enabled : ternary;
        multicast_metadata.mld_snooping_enabled : ternary;
#endif /* IPV6_DISABLE */
#endif /* L3_MULTICAST_DISABLE */
        l3_metadata.routed : ternary;
        ipv6_metadata.ipv6_src_is_link_local : ternary;
        l2_metadata.same_if_check : ternary;
#ifndef TUNNEL_DISABLE
        tunnel_metadata.tunnel_if_check : ternary;
#endif
#ifndef INGRESS_UC_SAME_BD_CHECK_DISABLE
        l3_metadata.same_bd_check : ternary;
#endif /* INGRESS_UC_SAME_BD_CHECK_DISABLE */
        l3_metadata.lkp_ip_ttl : ternary;
#if !defined(STP_DISABLE)
        l2_metadata.ingress_stp_check_fail : ternary;
#endif /* !STP_DISABLE */

#ifdef L2_SRC_MISS_MOVE_IN_SYSTEM_ACL_KEY_ENABLE
        l2_metadata.l2_src_miss     : ternary;
        l2_metadata.l2_src_move     : ternary;
#endif /* L2_SRC_MISS_MOVE_IN_SYSTEM_ACL_KEY_ENABLE */
        ipv4_metadata.ipv4_unicast_enabled : ternary;
#ifndef IPV6_DISABLE
        ipv6_metadata.ipv6_unicast_enabled : ternary;
#endif /* IPV6_DISABLE */

#ifdef L2_DST_MISS_IN_SYSTEM_ACL_KEY_ENABLE
        l2_metadata.l2_dst_miss : ternary;
#endif
        l2_metadata.lkp_pkt_type : ternary;
        l2_metadata.arp_opcode : ternary;
        /* egress information */
#ifdef EGRESS_IFINDEX_IN_SYSTEM_ACL_KEY_ENABLE
        ingress_metadata.egress_ifindex : ternary;
#endif

#ifdef REASON_CODE_IN_SYSTEM_ACL_KEY_ENABLE
        fabric_metadata.reason_code : ternary;
#endif
#ifdef DTEL_DROP_REPORT_ENABLE
        ig_intr_md_for_tm.drop_ctl : ternary;
        dtel_md.mod_watchlist_hit: ternary;
#endif
#ifdef IPV4_4_TUPLE_IN_SYSTEM_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IPV4_DA  : ternary;
        INGRESS_ACL_KEY_IP_PROTO : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;
#endif

#ifdef IPV4_IHL_IN_SYSTEM_ACL_KEY_ENABLE
        ipv4.ihl : ternary;
#endif
#ifdef IPV6_4_TUPLE_IN_SYSTEM_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IPV6_DA  : ternary;
#endif
#ifdef IPV4_FRAG_IN_SYSTEM_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_IP_FRAG : ternary;
#endif

#ifdef MAC_IN_SYSTEM_ACL_KEY_ENABLE
        INGRESS_ACL_KEY_MAC_DA           : ternary;
#endif

#ifdef DMAC_LABEL_ENABLE
        l2_metadata.dmac_label : ternary;
#endif /* DMAC_LABEL_ENABLE */

#ifdef METER_COLOR_IN_SYSTEM_ACL_KEY_ENABLE
        ig_intr_md_for_tm.packet_color : ternary;
#endif
#endif /* SYSTEM_FLOW_ACL_ENABLE */
}
    actions {
        nop;
        redirect_to_cpu;
        redirect_to_cpu_with_reason;
        copy_to_cpu;
        copy_to_cpu_with_reason;
        drop_packet;
        drop_packet_with_reason;
#ifdef LEARN_INVALIDATE_ENABLE
        invalidate_learn_digest;
        redirect_to_cpu_and_learn_inv;
        redirect_to_cpu_with_reason_and_learn_inv;
        copy_to_cpu_and_learn_inv;
        copy_to_cpu_with_reason_and_learn_inv;
        drop_packet_and_learn_inv;
        drop_packet_with_reason_and_learn_inv;
#endif /* LEARN_INVALIDATE_ENABLE */
#ifdef DTEL_DROP_REPORT_ENABLE
        mirror_and_drop;
        mirror_and_drop_with_reason;
#ifdef LEARN_INVALIDATE_ENABLE
        mirror_and_drop_and_learn_inv;
        mirror_and_drop_with_reason_and_learn_inv;
#endif /* LEARN_INVALIDATE_ENABLE */
#endif /* DTEL_DROP_REPORT_ENABLE */
#ifdef PORT_REDIRECT_IN_SYSTEM_ACL_ENABLE
      redirect_to_port;
#endif /* PORT_REDIRECT_IN_SYSTEM_ACL_ENABLE */
#ifdef DROP_CANCEL_IN_SYSTEM_ACL_ENABLE
        drop_cancel;
#endif
    }
    size : SYSTEM_ACL_SIZE;
}

#ifdef SAME_PORT_CHECK_ENABLE
action same_check_drop(drop_reason) {
    modify_field(ingress_metadata.drop_reason, drop_reason);
    modify_field(ingress_metadata.drop_flag, TRUE);
    drop();
}

action mirror_and_drop_same_check_drop(drop_reason) {
    modify_field(ingress_metadata.drop_reason, drop_reason);
#ifdef DTEL_DROP_REPORT_ENABLE
    mirror_and_drop();
#endif
}

table same_port_check_enable {
    reads {
        ingress_metadata.ingress_port : exact;
        ig_intr_md_for_tm.ucast_egress_port : exact;
#ifdef DTEL_DROP_REPORT_ENABLE
        dtel_md.mod_watchlist_hit: exact;
#endif
    }
    actions {
        nop;
        same_check_drop;
#ifdef DTEL_DROP_REPORT_ENABLE
        mirror_and_drop_same_check_drop;
#endif
    }
    default_action: nop;
    size : PORTMAP_TABLE_SIZE;
}
#endif

table ecn_egress_drop_acl {
  reads {
    eg_intr_md.egress_port : exact;
    qos_metadata.lkp_tc : exact;
  }
  actions {
    nop;
    drop_packet;
#ifdef DTEL_QUEUE_REPORT_ENABLE
    egress_mirror_and_drop_set_queue_alert;
#endif // DTEL_QUEUE_REPORT_ENABLE
  }
  default_action: nop;
  size : 1024;
}

action drop_stats_update() {
    count(drop_stats_2, ingress_metadata.drop_reason);
#ifdef ALT_INGRESS_DROP_ENABLE
    drop_packet();
#endif
}

table drop_stats {
    actions {
        drop_stats_update;
    }
    default_action : drop_stats_update;
    size : DROP_STATS_TABLE_SIZE;
}

#if defined(DTEL_DROP_REPORT_ENABLE) || \
    defined(DTEL_QUEUE_REPORT_ENABLE)
action invalidate_dod() {
    deflect_on_drop(FALSE);
}

table dod_control {
    reads {
        ig_intr_md_for_tm.mcast_grp_a  : exact;
        ig_intr_md_for_tm.mcast_grp_b  : exact;
        ig_intr_md_for_tm.copy_to_cpu  : exact;
    }

    actions {
        invalidate_dod;
        nop;
    }
    size: 3;
}
#endif

control process_system_acl {

    if (DO_LOOKUP(SYSTEM_ACL)) {
#ifdef PFC_ACL_ENABLE
        apply(ingress_pfc_acl) {
            nop {
#endif
#ifdef SAME_PORT_CHECK_ENABLE
                apply(same_port_check_enable) {
                    nop {
#endif
#ifdef SYSTEM_LOW_PRI_ACL_ENABLE
        if(ingress_metadata.port_type == PORT_TYPE_RECIRC) {
          apply(recirc_port_copy_to_cpu);
        } else {
          apply(system_reason_acl);
          if(acl_metadata.acl_entry_hit == 0 or ((acl_metadata.acl_deny == FALSE) and acl_metadata.acl_entry_hit == 1)) {
            //apply low priority system_acl only when user acl_hit = 0
            apply(system_acl_2);
          }
      }
      if(ingress_metadata.port_type == PORT_TYPE_NORMAL) {
        apply(system_acl) {
          nop {apply(copp_drop_2);} 
        }
      }
#else
        apply(system_acl);
#endif
#ifdef SAME_PORT_CHECK_ENABLE
                    }
                }
#endif
#ifdef PFC_ACL_ENABLE
            }
        }
#endif
        if (ingress_metadata.drop_flag == TRUE) {
            apply(drop_stats);
        }
#if (defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)) && \
    !defined(ALT_DOD_CONTROL)
        apply(dod_control);
#endif
#ifdef INGRESS_COPP_ENABLE
#ifdef ALT_SYSTEM_ACL_ENABLE
    apply(copp_drop) {
      on_miss { apply(color_action); }
    }
#else
	  apply(copp_drop);
#endif /* ALT_SYSTEM_ACL_ENABLE */
#endif /* INGRESS_COPP_ENABLE */
    }
}

/*****************************************************************************/
/* Egress ACL                                                                */
/*****************************************************************************/

#ifdef EGRESS_ACL_ENABLE

/*****************************************************************************/
/* Egress ACL Actions                                                        */
/*****************************************************************************/
action egress_acl_deny(acl_copy_reason, acl_stats_index) {
    modify_field(acl_metadata.egress_acl_deny, TRUE);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifdef EGRESS_ACL_STATS_ENABLE
    modify_field(acl_metadata.egress_acl_stats_index, acl_stats_index);
#endif /* EGRESS_ACL_STATS_ENABLE */
}

action egress_acl_permit(acl_copy_reason, acl_stats_index,acl_meter_index) {
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifdef EGRESS_ACL_STATS_ENABLE
    modify_field(acl_metadata.egress_acl_stats_index, acl_stats_index);
#endif /* EGRESS_ACL_STATS_ENABLE */
#ifdef EGRESS_METER_ENABLE
    modify_field(meter_metadata.egress_meter_index, acl_meter_index);
#endif /* EGRESS_METER_ENABLE */
}

action egress_acl_mirror(acl_stats_index,acl_meter_index, session_id) {
#ifdef EGRESS_ACL_STATS_ENABLE
    modify_field(acl_metadata.egress_acl_stats_index, acl_stats_index);
#endif /* EGRESS_ACL_STATS_ENABLE */
#ifdef EGRESS_METER_ENABLE
    modify_field(meter_metadata.egress_meter_index, acl_meter_index);
#endif /* EGRESS_METER_ENABLE */
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_egress_pkt_to_egress(session_id, e2e_mirror_info);
}

/*****************************************************************************/
/* Egress Mac ACL                                                            */
/*****************************************************************************/

#if !defined(L2_DISABLE) && !defined(EGRESS_MAC_ACL_DISABLE)
table egress_mac_acl {
    reads {
        EGRESS_MAC_ACL_KEY
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
#ifdef EGRESS_ACL_MIRROR_ACTION_ENABLE
#ifndef MIRROR_ACTION_IN_MAC_ACL_DISABLE
        egress_acl_mirror;
#endif
#endif
    }
    size : EGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* !L2_DISABLE && !EGRESS_MAC_ACL_DISABLE */

/*****************************************************************************/
/* Egress IPv4 ACL                                                           */
/*****************************************************************************/
#ifndef IPV4_DISABLE
table egress_ip_acl {
    reads {
        EGRESS_IPV4_ACL_KEY
#if defined(EGRESS_ACL_RANGE_DISABLE)
        EGRESS_ACL_KEY_L4_SPORT         : ternary;
        EGRESS_ACL_KEY_L4_DPORT         : ternary;
#else
        EGRESS_ACL_KEY_L4_SPORT_RANGE   : ternary;
        EGRESS_ACL_KEY_L4_DPORT_RANGE   : ternary;
#endif /* !EGRESS_ACL_RANGE_DISABLE */
#ifdef DSCP_IN_EGRESS_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_IPV4_DSCP        : ternary;
#endif /* DSCP_IN_EGRESS_ACL_KEY_ENABLE */
#ifdef TCP_FLAGS_IN_EGRESS_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_TCP_FLAGS        : ternary;
#endif
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
#ifdef EGRESS_ACL_MIRROR_ACTION_ENABLE
        egress_acl_mirror;
#endif
    }
    size : EGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */

/*****************************************************************************/
/* Egress IPv6 ACL                                                           */
/*****************************************************************************/
#ifndef IPV6_DISABLE
#if defined(Q0_PROFILE)
@pragma stage 7
#endif
table egress_ipv6_acl {
    reads {
        EGRESS_IPV6_ACL_KEY
#if defined(EGRESS_ACL_RANGE_DISABLE)
        EGRESS_ACL_KEY_L4_SPORT         : ternary;
        EGRESS_ACL_KEY_L4_DPORT         : ternary;
#else
        EGRESS_ACL_KEY_L4_SPORT_RANGE   : ternary;
        EGRESS_ACL_KEY_L4_DPORT_RANGE   : ternary;
#endif /* !EGRESS_ACL_RANGE_DISABLE */
#ifdef DSCP_IN_EGRESS_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_IPV6_DSCP        : ternary;
#endif /* DSCP_IN_EGRESS_ACL_KEY_ENABLE */
#ifdef TCP_FLAGS_IN_EGRESS_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_TCP_FLAGS        : ternary;
#endif
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
#ifdef EGRESS_ACL_MIRROR_ACTION_ENABLE
        egress_acl_mirror;
#endif
    }
    size : EGRESS_IPV6_ACL_TABLE_SIZE;
}

#endif /* IPV6_DISABLE */
#endif /* EGRESS_ACL_ENABLE */

/*****************************************************************************/
/* Egress ACL Control flow                                                   */
/*****************************************************************************/
control process_egress_acl {
#ifdef EGRESS_ACL_ENABLE
    if (valid(ipv4)) {
#ifndef IPV4_DISABLE
        apply(egress_ip_acl);
#endif /* IPV4_DISABLE */
    } else {
        if (valid(ipv6)) {
#ifndef IPV6_DISABLE
            apply(egress_ipv6_acl);
#endif /* IPV6_DISABLE */
#if !defined(L2_DISABLE) && !defined(EGRESS_MAC_ACL_DISABLE)
        } else {
            apply(egress_mac_acl);
#endif /* !L2_DISABLE && !EGRESS_MAC_ACL_DISABLE */
        }
    }
#endif /* EGRESS_ACL_ENABLE */
}

/*****************************************************************************/
/* Egress IPv4 Mirror ACL                                                    */
/*****************************************************************************/
#if !defined(IPV4_DISABLE) && defined(EGRESS_MIRROR_ACL_ENABLE)
#if defined(MSDC_IPV4_PROFILE)
@pragma stage 5
#endif /* MSDC_IPV4_PROFILE */
table egress_ipv4_mirror_acl {
    reads {
        EGRESS_ACL_KEY_PORT_LABEL       : ternary;
        EGRESS_ACL_KEY_IPV4_SA          : ternary;
        EGRESS_ACL_KEY_IPV4_DA          : ternary;
        EGRESS_ACL_KEY_IPV4_PROTO       : ternary;
#if defined(EGRESS_ACL_RANGE_DISABLE)
        EGRESS_ACL_KEY_L4_SPORT         : ternary;
        EGRESS_ACL_KEY_L4_DPORT         : ternary;
#else
        EGRESS_ACL_KEY_L4_SPORT_RANGE   : ternary;
        EGRESS_ACL_KEY_L4_DPORT_RANGE   : ternary;
#endif /* !EGRESS_ACL_RANGE_DISABLE */
#ifdef DSCP_IN_EGRESS_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_IPV4_DSCP        : ternary;
#endif /* DSCP_IN_EGRESS_ACL_KEY_ENABLE */
#ifdef ETYPE_IN_MIRROR_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_ETYPE : ternary;
#endif
    }
    actions {
        nop;
        egress_mirror;
    }
    size : MIRROR_ACL_TABLE_SIZE;
}
#endif /* !IPV4_DISABLE && EGRESS_MIRROR_ACL_ENABLE */

control process_egress_ipv4_mirror_acl {
#if !defined(IPV4_DISABLE) && defined(EGRESS_MIRROR_ACL_ENABLE)
    apply(egress_ipv4_mirror_acl);
#endif /* !IPV4_DISABLE && EGRESS_MIRROR_ACL_ENABLE */
}

/*****************************************************************************/
/* Egress Ipv6 Mirror ACL                                                    */
/*****************************************************************************/
#if !defined(IPV6_DISABLE) && defined(EGRESS_MIRROR_ACL_ENABLE)
#if defined(MSDC_IPV4_PROFILE)
@pragma stage 5
#endif /* MSDC_IPV4_PROFILE */
table egress_ipv6_mirror_acl {
    reads {
        EGRESS_ACL_KEY_PORT_LABEL       : ternary;
        EGRESS_ACL_KEY_IPV6_SA          : ternary;
        EGRESS_ACL_KEY_IPV6_DA          : ternary;
        EGRESS_ACL_KEY_IPV6_PROTO       : ternary;
#if defined(EGRESS_ACL_RANGE_DISABLE)
        EGRESS_ACL_KEY_L4_SPORT         : ternary;
        EGRESS_ACL_KEY_L4_DPORT         : ternary;
#else
        EGRESS_ACL_KEY_L4_SPORT_RANGE   : ternary;
        EGRESS_ACL_KEY_L4_DPORT_RANGE   : ternary;
#endif /* !EGRESS_ACL_RANGE_DISABLE */
#ifdef DSCP_IN_EGRESS_ACL_KEY_ENABLE
        EGRESS_ACL_KEY_IPV6_DSCP        : ternary;
#endif /* DSCP_IN_EGRESS_ACL_KEY_ENABLE */
    }
    actions {
        nop;
        egress_mirror;
    }
    size : MIRROR_ACL_TABLE_SIZE;
}
#endif /* !IPV6_DISABLE && EGRESS_MIRROR_ACL_ENABLE */

control process_egress_ipv6_mirror_acl {
#if !defined(IPV6_DISABLE) && defined(EGRESS_MIRROR_ACL_ENABLE)
    apply(egress_ipv6_mirror_acl);
#endif /* !IPV6_DISABLE && EGRESS_MIRROR_ACL_ENABLE */
}

/*****************************************************************************/
/* Egress ACL stats                                                          */
/*****************************************************************************/
#ifdef EGRESS_ACL_STATS_ENABLE
counter egress_acl_stats {
    type : packets_and_bytes;
    instance_count : EGRESS_ACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action egress_acl_stats_update() {
    count(egress_acl_stats, acl_metadata.egress_acl_stats_index);
}

table egress_acl_stats {
    actions {
        egress_acl_stats_update;
    }
    default_action : egress_acl_stats_update;
    size : EGRESS_ACL_STATS_TABLE_SIZE;
}
#endif /* EGRESS_ACL_STATS_ENABLE */

control process_egress_acl_stats {
#ifdef EGRESS_ACL_STATS_ENABLE
    apply(egress_acl_stats);
#endif /* EGRESS_ACL_STATS_ENABLE */
}

#ifdef MIRROR_ACL_STATS_ENABLE
counter egress_mirror_acl_stats {
 type : packets_and_bytes;
 instance_count : MIRROR_ACL_STATS_TABLE_SIZE;
 min_width : 16;
}

action egress_mirror_acl_stats_update() {
  count(egress_mirror_acl_stats, acl_metadata.egress_mirror_acl_stats_index);
}

table egress_mirror_acl_stats {
  actions {
    egress_mirror_acl_stats_update;
  }
  default_action : egress_mirror_acl_stats_update;
 size : MIRROR_ACL_STATS_TABLE_SIZE;
}
#endif /* MIRROR_ACL_STATS_ENABLE */

control process_egress_mirror_acl_stats {
#ifdef MIRROR_ACL_STATS_ENABLE
    apply(egress_mirror_acl_stats);
#endif /* EGRESS_ACL_STATS_ENABLE */
}

/*****************************************************************************/
/* Egress System ACL                                                         */
/*****************************************************************************/

#if defined(DTEL_QUEUE_REPORT_ENABLE) || \
    defined(DTEL_DROP_REPORT_ENABLE)
field_list e2e_mirror_and_drop_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
    ingress_metadata.drop_reason;
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    ig_intr_md_for_tm.qid;
    dtel_md.flow_hash;
#ifdef INT_EP_ENABLE
    int_metadata.source;
    int_metadata.sink;
#endif // INT_EP_ENABLE;
#ifdef INT_TRANSIT_ENABLE
    int_metadata.path_tracking_flow;
#endif // INT_TRANSIT_ENABLE
#ifdef POSTCARD_ENABLE
    postcard_md.report;
#endif // POSTCARD_ENABLE;
#ifdef DTEL_QUEUE_REPORT_ENABLE
    dtel_md.queue_alert;
#endif // DTEL_QUEUE_REPORT_ENABLE
    dtel_md.mod_watchlist_hit;
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
    dtel_md.drop_flow_suppress;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
}
#endif /* DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE*/

action egress_mirror(session_id, acl_stats_index) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_egress_pkt_to_egress(session_id, e2e_mirror_info);
#ifdef MIRROR_ACL_STATS_ENABLE
    modify_field(acl_metadata.egress_mirror_acl_stats_index, acl_stats_index);
#endif /* MIRROR_ACL_STATS_ENABLE */
}

action egress_mirror_and_drop(reason_code) {
    // This is used for cases like mirror on drop where
    // original frame needs to be dropped after mirror copy is made
#if defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)
    modify_field(ingress_metadata.drop_reason, reason_code);
    modify_field(i2e_metadata.mirror_session_id,
                 dtel_md.mirror_session_id);
    clone_egress_pkt_to_egress(dtel_md.mirror_session_id,
                               e2e_mirror_and_drop_info);
#endif /* DTEL_DROP_REPORT_ENABLE || DTEL_QUEUE_REPORT_ENABLE */
    drop();
}

#ifdef DTEL_QUEUE_REPORT_ENABLE
// if eg_intr_md.deflection_flag and dtel_md.queue_dod_enable are both set
action egress_mirror_and_drop_set_queue_alert(reason_code) {
    modify_field(dtel_md.queue_alert, 1);
    egress_mirror_and_drop(reason_code);
}
#endif // DTEL_QUEUE_REPORT_ENABLE

action egress_copy_to_cpu() {
    clone_egress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
}

action egress_redirect_to_cpu() {
    egress_copy_to_cpu();
    drop();
}

action egress_copy_to_cpu_with_reason(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
    egress_copy_to_cpu();
}

action egress_redirect_to_cpu_with_reason(reason_code) {
    egress_copy_to_cpu_with_reason(reason_code);
    drop();
}

// Example of coal_mirroring with small sample header
action egress_mirror_coal_hdr(session_id, id) {
#ifdef COALESCED_MIRROR_ENABLE
    add_header(coal_sample_hdr);
    modify_field(coal_sample_hdr.id, id);
    // Just make sure extract len (64) will not be > pkt_len
    sample_e2e(session_id, 64, coal_sample_hdr);
#endif
}

action egress_insert_cpu_timestamp() {
#ifdef PTP_ENABLE
  add_header(fabric_header_timestamp);
  modify_field(fabric_header_timestamp.arrival_time, i2e_metadata.ingress_tstamp);
  modify_field(fabric_header_timestamp.arrival_time_hi,
        i2e_metadata.ingress_tstamp_hi);
#endif /* PTP_ENABLE */
}

#ifdef EGRESS_SYSTEM_ACL_STATS_ENABLE
counter egress_system_acl_stats {
    type : packets;
    direct : egress_system_acl;
    min_width : 16;
}
#endif

#ifdef PORT_DROP_STATS_ENABLE
action egress_drop_packet_with_reason(drop_reason) {
    modify_field(egress_metadata.drop_reason, drop_reason);
    drop();
}
#endif /* PORT_DROP_STATS_ENABLE */

table egress_system_acl {
    reads {
        fabric_metadata.reason_code : ternary;
#ifdef COPP_COLOR_DROP_ENABLE
        ig_intr_md_for_tm.packet_color : ternary;
#endif
#ifdef EGRESS_METER_ENABLE
        meter_metadata.egress_meter_packet_color : ternary;
        meter_metadata.egress_meter_drop : ternary;
#endif
        eg_intr_md.egress_port : ternary;
        eg_intr_md.deflection_flag : ternary;
        l3_metadata.l3_mtu_check : ternary;
#if !defined(STP_DISABLE)
        l2_metadata.egress_stp_check_fail : ternary;
#endif /* !STP_DISABLE */
#ifdef MLAG_ENABLE
        l2_metadata.ingress_port_is_peer_link : ternary;
        l2_metadata.egress_port_is_mlag_member : ternary;
#endif /* MLAG_ENABLE */
#ifdef WRED_DROP_ENABLE
        wred_metadata.drop_flag : ternary;
#endif
#ifdef EGRESS_ACL_ENABLE
        acl_metadata.egress_acl_deny : ternary;
#endif /* EGRESS_ACL_ENABLE */
#ifdef DTEL_DROP_REPORT_ENABLE
        eg_intr_md_for_oport.drop_ctl : ternary;
        dtel_md.mod_watchlist_hit : ternary;
#endif
#ifdef DTEL_QUEUE_REPORT_ENABLE
        dtel_md.queue_dod_enable : ternary;
#endif
#ifdef DTEL_DROP_FLOW_STATE_TRACK_ENABLE
        dtel_report_header.valid : ternary;
        dtel_md.drop_flow_suppress : ternary;
#endif // DTEL_DROP_FLOW_STATE_TRACK_ENABLE
#ifdef INGRESS_PORT_IN_EGRESS_SYSTEM_ACL_ENABLE
        ingress_metadata.ingress_port : ternary;
#endif
    }
    actions {
        nop;
        drop_packet;
#ifdef PORT_DROP_STATS_ENABLE
        egress_drop_packet_with_reason;
#endif /* PORT_DROP_STATS_ENABLE */
        egress_copy_to_cpu;
        egress_redirect_to_cpu;
        egress_copy_to_cpu_with_reason;
        egress_redirect_to_cpu_with_reason;
        egress_mirror_coal_hdr;
#ifdef PTP_ENABLE
	egress_insert_cpu_timestamp;
#endif /* PTP_ENABLE */
#ifndef MIRROR_DISABLE
        egress_mirror;
        egress_mirror_and_drop;
#ifdef DTEL_QUEUE_REPORT_ENABLE
        egress_mirror_and_drop_set_queue_alert;
#endif // DTEL_QUEUE_REPORT_ENABLE
#endif /* MIRROR_DISABLE */
    }
    size : EGRESS_SYSTEM_ACL_TABLE_SIZE;
}

control process_egress_system_acl {
    if (egress_metadata.bypass == FALSE) {
        apply(egress_system_acl);
    }
}

#ifdef PORT_DROP_STATS_ENABLE
counter ingress_port_drop_stats {
    type : packets;
    direct : ingress_port_drop_stats;
}

table ingress_port_drop_stats {
    reads {
        ingress_metadata.ingress_port mask 0x3f: exact;
        ingress_metadata.drop_reason: exact;
    }
    actions {
        nop;
    }
    default_action : nop();
    size : PORT_DROP_STATS_TABLE_SIZE;
}

control process_ingress_port_drop_stats {
    if (ingress_metadata.drop_reason != 0)
        apply(ingress_port_drop_stats);
}
#endif /* PORT_DROP_STATS_ENABLE */

#ifdef EGRESS_PORT_DROP_STATS_ENABLE
counter egress_port_drop_stats {
    type : packets;
    direct : egress_port_drop_stats;
}

table egress_port_drop_stats {
    reads {
        egress_metadata.egress_port : exact;
        egress_metadata.drop_reason: exact;
    }
    actions {
        nop;
    }
    size : PORT_DROP_STATS_TABLE_SIZE;
}


control process_egress_port_drop_stats {
    if (egress_metadata.drop_reason != 0)
        apply(egress_port_drop_stats);
}
#endif /* EGRESS_PORT_DROP_STATS_ENABLE */
