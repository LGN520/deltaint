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
 * Segment routing processing
 */

#ifdef SRV6_ENABLE

header_type sr_metadata_t {
    fields {
        endpoint_hit : 1;
        srh_len : 16;
    }
}

metadata sr_metadata_t sr_metadata;


/******************************************************************************/
/* Local SID lookup                                                           */
/******************************************************************************/

//action l3vpn_term() {
  //    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
//}
action l3vpn_term(bd, vrf,
		  bd_label, stats_idx, rmac_group,
		  ipv4_unicast_enabled, ipv6_unicast_enabled,
		  ipv4_urpf_mode, ipv6_urpf_mode,
		  igmp_snooping_enabled, mld_snooping_enabled,
		  ipv4_multicast_enabled, ipv6_multicast_enabled,
		  mrpf_group,
		  ipv4_mcast_key, ipv4_mcast_key_type,
		  ipv6_mcast_key, ipv6_mcast_key_type) {
    modify_field(ingress_metadata.bd, bd);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
}

action l2vpn_term() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
}

@pragma ignore_table_dependency port_vlan_to_bd_mapping
@pragma ignore_table_dependency cpu_packet_transform
table my_sid {
    reads {
        ig_intr_md.ingress_port : ternary;
        ipv6.nextHdr : ternary; 
        ethernet.dstAddr : ternary;
        ipv6.dstAddr : lpm;
    }
    //    action_profile: bd_action_profile;
    actions {
        nop;
        l3vpn_term;
        l2vpn_term;
    }
    size : SRV6_LOCAL_SID_TABLE_SIZE;
}

action terminate_srv6_inner_non_ip() {
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_NONE);
    modify_field(l2_metadata.non_ip_packet, TRUE);
}

#ifndef IPV4_DISABLE
action terminate_srv6_inner_ethernet_ipv4() {
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr);

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
//    modify_field(ipv4_metadata.lkp_ipv4_sa,  inner_ipv4.srcAddr);
//    modify_field(ipv4_metadata.lkp_ipv4_da,  inner_ipv4.dstAddr);
//    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv4.protocol);
//    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv4.ttl);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv4.diffserv);

    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_tcp_flags);
}

action terminate_srv6_inner_ipv4() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(tunnel_metadata.l3_tunnel_terminate, TRUE);

    modify_field(l2_metadata.lkp_mac_type, ETHERTYPE_IPV4);
//    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr); // not valid
//    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr); // not valid

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
//    modify_field(ipv4_metadata.lkp_ipv4_sa,  inner_ipv4.srcAddr);
//    modify_field(ipv4_metadata.lkp_ipv4_da,  inner_ipv4.dstAddr);
//    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv4.protocol);
//    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv4.ttl);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv4.diffserv);

//    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_l4_sport);
//    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_tcp_flags);
}
#endif /* IPV4_DISABLE */

#ifndef INNER_IPV6_DISABLE
action terminate_srv6_inner_ethernet_ipv6() {
    
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
//    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr);
//    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr);
    
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
//    modify_field(ipv6_metadata.lkp_ipv6_sa,  inner_ipv6.srcAddr);
//    modify_field(ipv6_metadata.lkp_ipv6_da,  inner_ipv6.dstAddr);
//    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv6.nextHdr);
//    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv6.hopLimit);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv6.trafficClass);
    
    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_tcp_flags);
}

action terminate_srv6_inner_ipv6() {
    modify_field(tunnel_metadata.l3_tunnel_terminate, TRUE);
    
    modify_field(l2_metadata.lkp_mac_type, ETHERTYPE_IPV6);
//    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr); // not-valid
//    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr); // not-valid
    
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
//    modify_field(ipv6_metadata.lkp_ipv6_sa,  inner_ipv6.srcAddr);
//    modify_field(ipv6_metadata.lkp_ipv6_da,  inner_ipv6.dstAddr);
//    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv6.nextHdr);
//    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv6.hopLimit);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv6.trafficClass);
    
    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_tcp_flags);
}
#endif /* INNER_IPV6_DISABLE */

table adjust_lkp_fields_inner {
    reads {
        inner_ipv4 : valid;
        inner_ipv6 : valid;
    }
    actions {
        terminate_srv6_inner_non_ip;
        terminate_srv6_inner_ipv4;
        terminate_srv6_inner_ethernet_ipv4;
#ifndef INNER_IPV6_DISABLE
        terminate_srv6_inner_ipv6;
        terminate_srv6_inner_ethernet_ipv6;
#endif /* INNER_IPV6_DISABLE */
    }
    size : SRV6_FUNCTION_TABLE_SIZE;
}

/******************************************************************************/
/* SR tunnel decap                                                            */
/******************************************************************************/

action remove_ipv6_srh() {
    remove_header(ipv6_srh);
    remove_header(ipv6_srh_seg_list[0]);
#ifndef SRH_MAX_SEGMENTS_1
    remove_header(ipv6_srh_seg_list[1]);
    remove_header(ipv6_srh_seg_list[2]);
#endif /* SRH_MAX_SEGMENTS_1 */
}

action decap_sr_inner_non_ip() {
    copy_header(ethernet, inner_ethernet);
    remove_header(inner_ethernet);
    remove_header(ipv6);
    remove_ipv6_srh();
}

action decap_sr_inner_ipv4() {
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
    copy_header(ipv4, inner_ipv4);
    remove_header(inner_ipv4);
    remove_header(ipv6);
    remove_ipv6_srh();

}

action decap_sr_inner_ipv6() {
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
    copy_header(ipv6, inner_ipv6);
    remove_header(inner_ipv6);
    remove_ipv6_srh();
}

/******************************************************************************/
/* SR rewrite                                                                 */
/******************************************************************************/
/*
table srv6_rewrite {
    reads {
        sr_metadata.endpoint_hit : exact;
        ipv6_srh : valid;
        ipv6_srh.segLeft : ternary;
    }

    actions {
        nop;
        rewrite_ipv6_srh;
        rewrite_ipv6_and_remove_srh;
    }
}
*/

//table process_srh_len {
//    reads {
//        ipv6_srh : valid;
//        ipv6_srh.hdrExtLen : exact;
//    }
//    actions {
//        nop;
//        calculate_srh_total_len;
//    }
//}
//
//action rewrite_ipv6_and_remove_srh() {
//    subtract_from_field(ipv6_srh.segLeft, 1);
//    modify_field(ipv6.nextHdr, ipv6_srh.nextHdr);
//    subtract_from_field(ipv6.payloadLen, sr_metadata.srh_len);
//    remove_header(ipv6_srh);
//    remove_header(ipv6_srh_seg_list[0]);
//#ifndef SRH_MAX_SEGMENTS_1
//    remove_header(ipv6_srh_seg_list[1]);
//    remove_header(ipv6_srh_seg_list[2]);
//#endif /* SRH_MAX_SEGMENTS_1 */
//}
//
//action rewrite_ipv6_srh(srh_len) {
//    subtract_from_field(ipv6_srh.segLeft, 1);
//}
//
//action calculate_srh_total_len(total_len) {
//    // Precomputed values for SRH total length.
//    // total_len = (ipv6_srh.hdrExtLen << 3) + 8
//    add_to_field(sr_metadata.srh_len, total_len);
//}
//
/******************************************************************************/
/* SR tunnel encap                                                            */
/******************************************************************************/
//action f_insert_ipv6_srh(proto) {
//    add_header(ipv6_srh);
//    modify_field(ipv6_srh.nextHdr, proto);
//    modify_field(ipv6_srh.hdrExtLen, 0);
//    modify_field(ipv6_srh.routingType, 0x4);
//    modify_field(ipv6_srh.segLeft, 0);
//    modify_field(ipv6_srh.lastEntry, 0);
//    modify_field(ipv6_srh.flags, 0);
//    modify_field(ipv6_srh.tag, 0);
//}
//
//action srv6_rewrite() {
//    f_insert_ipv6_header(IP_PROTOCOLS_ROUTING);
//    f_insert_ipv6_srh(tunnel_metadata.inner_ip_proto);
//    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
//}
//
//action set_srh_rewrite(srh_len, seg_left) {
//    modify_field(ipv6_srh.hdrExtLen, srh_len);
//    modify_field(ipv6_srh.segLeft, seg_left);
//    modify_field(ipv6_srh.lastEntry, seg_left);
//}
//
//action set_srv6_rewrite_segments1(
//	sid0, ipv6_sa, outer_bd, smac_idx, sip_index, dip_index) {
//    set_ipv6_tunnel_rewrite_details(ipv6_sa);
//    add_header(ipv6_srh_seg_list[0]);
//    modify_field(ipv6_srh_seg_list[0].sid, sid0);
//    add(ipv6.payloadLen, egress_metadata.payload_length, 0x18);
//    set_srh_rewrite(0x2, 0);
//}
//
//#ifndef SRH_MAX_SEGMENTS_1
//action set_srv6_rewrite_segments2(
//	sid0, sid1, ipv6_sa, outer_bd, smac_idx, sip_index, dip_index) {
//    set_ipv6_tunnel_rewrite_details(ipv6_sa);
//    add_header(ipv6_srh_seg_list[0]);
//    add_header(ipv6_srh_seg_list[1]);
//    modify_field(ipv6_srh_seg_list[0].sid, sid0);
//    modify_field(ipv6_srh_seg_list[1].sid, sid1);
//    add(ipv6.payloadLen, egress_metadata.payload_length, 0x28);
//    set_srh_rewrite(0x4, 1);
//}
//
//action set_srv6_rewrite_segments3(
//	sid0, sid1, sid2, ipv6_sa, outer_bd, smac_idx, sip_index, dip_index) {
//    set_ipv6_tunnel_rewrite_details(ipv6_sa);
//    add_header(ipv6_srh_seg_list[0]);
//    add_header(ipv6_srh_seg_list[1]);
//    add_header(ipv6_srh_seg_list[2]);
//    modify_field(ipv6_srh_seg_list[0].sid, sid0);
//    modify_field(ipv6_srh_seg_list[1].sid, sid1);
//    modify_field(ipv6_srh_seg_list[2].sid, sid2);
//    add(ipv6.payloadLen, egress_metadata.payload_length, 0x38);
//    set_srh_rewrite(0x6, 2);
//}
//#endif /* SRH_MAX_SEGMENTS_1 */
//
#endif /* SRV6_ENABLE */
//
//
//control process_srv6_rewrite {
//#ifdef SRV6_ENABLE
//  //    apply(process_srh_len);
//  //    apply(srv6_rewrite);
//#endif /* SRV6_ENABLE */
//}
//
//control process_srv6 {
//#ifdef SRV6_ENABLE
//    if (valid(ipv6)) {
//        apply(srv6_sid);
//    }
//#endif /* SRV6_ENABLE */
//}
