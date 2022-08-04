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
 * Mirror processing
 */

action set_mirror_bd(bd, session_id, queue_id) {
    modify_field(egress_metadata.bd, bd);
    modify_field(i2e_metadata.mirror_session_id, session_id);
#ifdef EGRESS_QUEUE_STATS_ENABLE
    modify_field(ig_intr_md_for_tm.qid, queue_id);
#endif /* EGRESS_QUEUE_STATS_ENABLE */
}

action set_mirror_q(queue_id) {
    modify_field(ig_intr_md_for_tm.qid, queue_id);
}

action f_insert_erspan_common_header() {
    copy_header(inner_ethernet, ethernet);
    add_header(gre);
    add_header(erspan_t3_header);
    modify_field(gre.C, 0);
    modify_field(gre.R, 0);
    modify_field(gre.K, 0);
    modify_field(gre.S, 0);
    modify_field(gre.s, 0);
    modify_field(gre.recurse, 0);
    modify_field(gre.flags, 0);
    modify_field(gre.ver, 0);
    modify_field(gre.proto, GRE_PROTOCOLS_ERSPAN_T3);
#ifndef TIMESTAMP_DISABLE
    modify_field(erspan_t3_header.timestamp, i2e_metadata.ingress_tstamp);
#endif /* TIMESTAMP_DISABLE */
    modify_field(erspan_t3_header.priority_span_id, i2e_metadata.mirror_session_id);
    modify_field(erspan_t3_header.version, 2);
    modify_field(erspan_t3_header.vlan, 0);
}

action f_insert_erspan_t3_header() {
    f_insert_erspan_common_header();
    modify_field(erspan_t3_header.ft_d_other, 0);
}

action f_insert_ipv4_erspan_t3_header(sip, dip, tos, ttl) {
    f_insert_erspan_t3_header();
    add_header(ipv4);
    modify_field(ipv4.protocol, IP_PROTOCOLS_GRE);
    modify_field(ipv4.ttl, ttl);
    modify_field(ipv4.version, 0x4);
    modify_field(ipv4.ihl, 0x5);
    modify_field(ipv4.identification, 0);
    modify_field(ipv4.flags, 0x2);
    modify_field(ipv4.diffserv, tos);
    // IPv4 (20) + GRE (4) + Erspan (12)
    add(ipv4.totalLen, eg_intr_md.pkt_length, 36);
    modify_field(ipv4.srcAddr, sip);
    modify_field(ipv4.dstAddr, dip);
}

#ifdef MIRROR_NEXTHOP_DISABLE
action ipv4_erspan_t3_rewrite_with_eth_hdr(smac, dmac, sip, dip, tos, ttl, queue_id) {
    f_insert_ipv4_erspan_t3_header(sip, dip, tos, ttl);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, dmac);
#ifdef EGRESS_QUEUE_STATS_ENABLE
    modify_field(ig_intr_md_for_tm.qid, queue_id);
#endif /* EGRESS_QUEUE_STATS_ENABLE */
}

action ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag(smac, dmac, sip, dip, tos, ttl, vlan_tpid, vlan_id, cos, queue_id) {
    f_insert_ipv4_erspan_t3_header(sip, dip, tos, ttl);
    add_header(vlan_tag_[0]);
    modify_field(ethernet.etherType, vlan_tpid);
    modify_field(vlan_tag_[0].etherType, ETHERTYPE_IPV4);
    modify_field(vlan_tag_[0].vid, vlan_id);
    modify_field(vlan_tag_[0].pcp, cos);
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, dmac);
#ifdef EGRESS_QUEUE_STATS_ENABLE
    modify_field(ig_intr_md_for_tm.qid, queue_id);
#endif /* EGRESS_QUEUE_STATS_ENABLE */
}

#else
action ipv4_erspan_t3_rewrite(sip, dip, tos, ttl, queue_id) {
    f_insert_ipv4_erspan_t3_header(sip, dip, tos, ttl);
    // IPv4 (20) + GRE (4) + Erspan (12) + Ethernet (14)
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
#ifdef EGRESS_QUEUE_STATS_ENABLE
    modify_field(ig_intr_md_for_tm.qid, queue_id);
#endif /* EGRESS_QUEUE_STATS_ENABLE */
}
#endif

#ifdef DTEL_REPORT_ENABLE
action dtel_mirror_encap(smac, sip, dip) {
    copy_header(inner_ethernet, ethernet);
    add_header(udp);
    add_header(dtel_report_header);

    modify_field(udp.dstPort, 0); // will be set in later stage
    modify_field(l3_metadata.egress_l4_sport, i2e_metadata.mirror_session_id);
    modify_field(l3_metadata.egress_l4_dport, 0); // will be set in later stage
    modify_field(udp.checksum, 0);
    add(udp.length_, eg_intr_md.pkt_length, 20);

    modify_field(dtel_report_header.merged_fields, 0);
    modify_field(dtel_report_header.sequence_number, 0);
#ifndef TIMESTAMP_DISABLE
    modify_field(dtel_report_header.timestamp, i2e_metadata.ingress_tstamp);
#endif
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
    add(ipv4.totalLen, eg_intr_md.pkt_length, 40);

    modify_field(ipv4.srcAddr, sip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(ethernet.srcAddr, smac);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_DTEL);
}

action dtel_mirror_encap_without_entropy(smac, sip, dip, udp_src_port) {
    dtel_mirror_encap(smac, sip, dip);
    modify_field(udp.srcPort, udp_src_port);
}

action dtel_mirror_encap_with_entropy(smac, sip, dip) {
    dtel_mirror_encap(smac, sip, dip);
    modify_field(udp.srcPort, dtel_md.flow_hash);
}
#endif /* DTEL_REPORT_ENABLE */

@pragma ignore_table_dependency rid
@pragma egress_pkt_length_stage 0
#ifdef L3_HEAVY_INT_SPINE_PROFILE
@pragma stage 1
#endif
table mirror {
    reads {
        i2e_metadata.mirror_session_id : exact;
    }
    actions {
        nop;
        set_mirror_bd;
#ifdef MIRROR_NEXTHOP_DISABLE
        ipv4_erspan_t3_rewrite_with_eth_hdr;
        ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag;
#else
        ipv4_erspan_t3_rewrite;
#endif
#ifdef SFLOW_ENABLE
        sflow_pkt_to_cpu;
#endif
#ifdef DTEL_REPORT_ENABLE
        dtel_mirror_encap_without_entropy;
        dtel_mirror_encap_with_entropy;
#endif
//Used for local mirror
#ifdef EGRESS_QUEUE_STATS_ENABLE
        set_mirror_q;
#endif /* EGRESS_QUEUE_STATS_ENABLE */
    }
    size : MIRROR_SESSIONS_TABLE_SIZE;
}

control process_mirroring {
#ifndef MIRROR_DISABLE
    apply(mirror);
#endif /* MIRROR_DISABLE */
}

/*****************************************************************************/
/* Ingress Port Mirroring                                                    */
/*****************************************************************************/

action set_ingress_port_mirror_index(session_id) {
  modify_field(i2e_metadata.mirror_session_id, session_id);
  clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
}

#if defined(GENERIC_INT_LEAF_PROFILE) || \
    defined(MSDC_LEAF_DTEL_INT_PROFILE)
@pragma ternary 1
@pragma stage 1
#endif
table ingress_port_mirror {
  reads {
    ig_intr_md.ingress_port : exact;
  }
  actions {
    set_ingress_port_mirror_index;
    nop;
  }
  size: PORT_TABLE_SIZE;
}

control process_ingress_port_mirroring {
  apply(ingress_port_mirror);
}

/*****************************************************************************/
/* Egress Port Mirroring                                                     */
/*****************************************************************************/

action set_egress_port_mirror_index(session_id) {
  modify_field(i2e_metadata.mirror_session_id, session_id);
  clone_egress_pkt_to_egress(session_id, e2e_mirror_info);
}

#if defined(GENERIC_INT_LEAF_PROFILE) || defined(L3_HEAVY_INT_LEAF_PROFILE) \
    || defined(L3_HEAVY_INT_SPINE_PROFILE) || defined(GENERIC_INT_SPINE_PROFILE) || defined(Q0_PROFILE)
@pragma stage 0
@pragma ternary 1
#endif
table egress_port_mirror {
  reads {
    eg_intr_md.egress_port : exact;
  }
  actions {
    set_egress_port_mirror_index;
    nop;
  }
  size: PORT_TABLE_SIZE;
}

control process_egress_port_mirroring {
  apply(egress_port_mirror);
}
