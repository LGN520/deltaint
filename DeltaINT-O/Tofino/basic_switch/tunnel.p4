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
 * Tunnel processing
 */

/*
 * Tunnel metadata
 */
header_type tunnel_metadata_t {
    fields {
        ingress_tunnel_type : 4;               /* tunnel type from parser */
        tunnel_vni : 24;                       /* tunnel id */
        mpls_enabled : 1;                      /* is mpls enabled on BD */
        mpls_ttl : 8;                          /* Mpls Ttl */
        mpls_exp : 3;                          /* Mpls Traffic Class */
        mpls_in_udp: 1;                        /* bit to indicate if mpls is in udp */
        egress_tunnel_type : 5;                /* type of tunnel */
        tunnel_index : 8;                      /* tunnel index */
        tunnel_dst_index : TUNNEL_DST_BIT_WIDTH; /* index to tunnel dst ip */
        tunnel_src_index : 8;                  /* index to tunnel src ip */
        tunnel_smac_index : 8;                 /* index to tunnel src mac */
        tunnel_dmac_index : TUNNEL_DMAC_BIT_WIDTH; /* index to tunnel dst mac */
        vnid : 24;                             /* tunnel vnid */
        tunnel_lookup : 1;                     /* lookup tunnel table */
        tunnel_terminate : 1;                  /* is tunnel being terminated? */
        l3_tunnel_terminate : 1;               /* tunnel termination with ip payload */
        tunnel_if_check : 1;                   /* tun terminate xor originate */
        egress_header_count: 4;                /* number of mpls header stack */
        inner_ip_proto : 8;                    /* Inner IP protocol */
        src_vtep_hit : 1;                      /* hit in the src vtep table */
        vtep_ifindex : IFINDEX_BIT_WIDTH;      /* vtep ingress ifindex */
        tunnel_term_type : 1;                  /* Point-to-point or multipoint-to-point tunnel */
    }
}

#ifdef DTEL_REPORT_LB_ENABLE
@pragma pa_no_overlay egress tunnel_metadata.tunnel_smac_index
#endif
#if defined(L3_IPV4_FIB_CLPM_PROFILE) || defined(ACL_IPV4_PROFILE)
@pragma pa_container_size ingress tunnel_metadata.tunnel_if_check 8
#endif
#if defined(ENT_DC_GENERAL_PROFILE) && defined(__p4c__)
@pragma pa_container_size ingress tunnel_metadata.tunnel_dst_index 16
#endif
//@pragma pa_container_size ingress tunnel_metadata.tunnel_lookup 8
metadata tunnel_metadata_t tunnel_metadata;

/*****************************************************************************/
/* Outer router mac lookup                                                   */
/*****************************************************************************/
#ifndef TUNNEL_DISABLE
action outer_rmac_hit() {
    // This assigment is un-necessary.
    modify_field(l3_metadata.rmac_hit, FALSE);
}

@pragma ternary 1
table outer_rmac {
    reads {
        l3_metadata.rmac_group : exact;
        ethernet.dstAddr : exact;
    }
    actions {
        on_miss;
        outer_rmac_hit;
    }
    size : OUTER_ROUTER_MAC_TABLE_SIZE;
}
#endif /* TUNNEL_DISABLE */

#ifdef ALT_TUNNEL_TERM_ENABLE
/*############################################################################/
/# Alternate Tunnel termination scheme                                       #/
/############################################################################*/

    /* Tunnel Termination Actions */
action terminate_tunnel_inner_non_ip() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);

    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr);

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_NONE);
    modify_field(l2_metadata.non_ip_packet, TRUE);
}

#ifndef IPV4_DISABLE
action terminate_tunnel_inner_ethernet_ipv4() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);

    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr);

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(ipv4_metadata.lkp_ipv4_sa,  inner_ipv4.srcAddr);
    modify_field(ipv4_metadata.lkp_ipv4_da,  inner_ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv4.ttl);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv4.diffserv);

    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_inner_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_inner_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_inner_tcp_flags);
}

action terminate_tunnel_inner_ipv4() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(tunnel_metadata.l3_tunnel_terminate, TRUE);

    modify_field(l2_metadata.lkp_mac_type, ETHERTYPE_IPV4);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr); // not valid
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr); // not valid

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(ipv4_metadata.lkp_ipv4_sa,  inner_ipv4.srcAddr);
    modify_field(ipv4_metadata.lkp_ipv4_da,  inner_ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv4.ttl);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv4.diffserv);

    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_inner_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_inner_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_inner_tcp_flags);
}
#endif /* IPV4_DISABLE */

#ifndef INNER_IPV6_DISABLE
action terminate_tunnel_inner_ethernet_ipv6() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr);
    
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(ipv6_metadata.lkp_ipv6_sa,  inner_ipv6.srcAddr);
    modify_field(ipv6_metadata.lkp_ipv6_da,  inner_ipv6.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv6.hopLimit);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv6.trafficClass);
    
    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_inner_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_inner_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_inner_tcp_flags);
}

action terminate_tunnel_inner_ipv6() {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(tunnel_metadata.l3_tunnel_terminate, TRUE);
    
    modify_field(l2_metadata.lkp_mac_type, ETHERTYPE_IPV6);
    modify_field(l2_metadata.lkp_mac_sa,   inner_ethernet.srcAddr); // not-valid
    modify_field(l2_metadata.lkp_mac_da,   inner_ethernet.dstAddr); // not-valid
    
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(ipv6_metadata.lkp_ipv6_sa,  inner_ipv6.srcAddr);
    modify_field(ipv6_metadata.lkp_ipv6_da,  inner_ipv6.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto,   inner_ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl,     inner_ipv6.hopLimit);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);
    modify_field(l3_metadata.lkp_dscp,       inner_ipv6.trafficClass);
    
    modify_field(l3_metadata.lkp_l4_sport,  l3_metadata.lkp_inner_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport,  l3_metadata.lkp_inner_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_inner_tcp_flags);
}
#endif /* INNER_IPV6_DISABLE */

#ifdef P2P_TUNNEL_TERM_ENABLE

#ifndef IPV4_TUNNEL_DISABLE
    /* IPv4 source and destination VTEP lookups */

table ipv4_vtep {
    reads {
        l3_metadata.vrf : ternary;
        ipv4.srcAddr : ternary;
        ipv4.dstAddr : ternary;
        tunnel_metadata.ingress_tunnel_type : ternary;
        inner_ethernet.valid : ternary;
        inner_ipv4.valid : ternary;
        inner_ipv6.valid : ternary;
    }
    actions {
        nop;
        terminate_tunnel_inner_non_ip;
        terminate_tunnel_inner_ipv4;
        terminate_tunnel_inner_ethernet_ipv4;
#ifndef INNER_IPV6_DISABLE
        terminate_tunnel_inner_ipv6;
        terminate_tunnel_inner_ethernet_ipv6;
#endif /* INNER_IPV6_DISABLE */
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}
#endif /* IPV4_TUNNEL_DISABLE */


#ifndef IPV6_TUNNEL_DISABLE
    /* IPv6 source and destination VTEP lookups */

table ipv6_vtep {
    reads {
        l3_metadata.vrf : ternary;
        ipv6.srcAddr : ternary;
        ipv6.dstAddr : ternary;
        tunnel_metadata.ingress_tunnel_type : ternary;
        inner_ethernet.valid : ternary;
        inner_ipv4.valid : ternary;
        inner_ipv6.valid : ternary;
    }
    actions {
        nop;
        terminate_tunnel_inner_non_ip;
        terminate_tunnel_inner_ipv4;
        terminate_tunnel_inner_ethernet_ipv4;
#ifndef INNER_IPV6_DISABLE
        terminate_tunnel_inner_ipv6;
        terminate_tunnel_inner_ethernet_ipv6;
#endif /* INNER_IPV6_DISABLE */
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}
#endif /* IPV6_TUNNEL_DISABLE */

#else /* P2P_TUNNEL_TERM_ENABLE */

action src_vtep_hit(ifindex) {
    modify_field(tunnel_metadata.src_vtep_hit, TRUE);
    modify_field(tunnel_metadata.vtep_ifindex, ifindex);
}

action src_vtep_hit_with_vni(ifindex, tunnel_vni) {
    modify_field(tunnel_metadata.src_vtep_hit, TRUE);
    modify_field(tunnel_metadata.vtep_ifindex, ifindex);
    modify_field(tunnel_metadata.tunnel_vni, tunnel_vni);
}

    /* IPv4 source and destination VTEP lookups */

#ifndef IPV4_TUNNEL_DISABLE
table ipv4_dest_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv4.dstAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
        inner_ipv4 : valid;
        inner_ipv6 : valid;
    }
    actions {
        nop;
        terminate_tunnel_inner_non_ip;
        terminate_tunnel_inner_ipv4;
        terminate_tunnel_inner_ethernet_ipv4;
#ifndef INNER_IPV6_DISABLE
        terminate_tunnel_inner_ipv6;
        terminate_tunnel_inner_ethernet_ipv6;
#endif /* INNER_IPV6_DISABLE */
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}

table ipv4_src_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv4.srcAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
    }
    actions {
        on_miss;
        src_vtep_hit;
        src_vtep_hit_with_vni;
    }
    size : IPV4_SRC_TUNNEL_TABLE_SIZE;
}
#endif /* IPV4_TUNNEL_DISABLE */

#ifndef IPV6_TUNNEL_DISABLE

    /* IPv6 source and destination VTEP lookups */

table ipv6_dest_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv6.dstAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
        inner_ipv4 : valid;
        inner_ipv6 : valid;
    }
    actions {
        nop;
        terminate_tunnel_inner_non_ip;
        terminate_tunnel_inner_ipv4;
        terminate_tunnel_inner_ethernet_ipv4;
#ifndef INNER_IPV6_DISABLE
        terminate_tunnel_inner_ipv6;
        terminate_tunnel_inner_ethernet_ipv6;
#endif /* INNER_IPV6_DISABLE */
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}

table ipv6_src_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv6.srcAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
    }
    actions {
        on_miss;
        src_vtep_hit;
        src_vtep_hit_with_vni;
    }
    size : IPV6_SRC_TUNNEL_TABLE_SIZE;
}
#endif /* IPV6_TUNNEL_DISABLE */
#endif /* P2P_TUNNEL_TERM_ENABLE */

    /* VNI -> BD Translation */
action set_ingress_vni_properties(bd, vrf, learning_enabled,
				  rmac_group, bd_label, ipv4_unicast_enabled,
				  ipv6_unicast_enabled, igmp_snooping_enabled,
				  mld_snooping_enabled, stats_idx, ipv4_multicast_enabled,
				  ipv6_multicast_enabled, mrpf_group,
				  exclusion_id, ingress_rid) {
    modify_field(ingress_metadata.bd, bd);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);
    modify_field(l2_metadata.learning_enabled, learning_enabled);
    modify_field(l3_metadata.vrf, vrf);
//    modify_field(ipv4_metadata.ipv4_unicast_enabled, TRUE);
//    modify_field(ipv6_metadata.ipv6_unicast_enabled, TRUE);
//    modify_field(ipv4_metadata.ipv4_multicast_enabled, TRUE);
//    modify_field(ipv6_metadata.ipv6_multicast_enabled, TRUE);
//    modify_field(multicast_metadata.igmp_snooping_enabled, TRUE);
//    modify_field(multicast_metadata.mld_snooping_enabled, TRUE);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
    modify_field(multicast_metadata.ipv4_multicast_enabled, ipv4_multicast_enabled);
    modify_field(multicast_metadata.ipv6_multicast_enabled, ipv6_multicast_enabled);
    modify_field(multicast_metadata.igmp_snooping_enabled, igmp_snooping_enabled);
    modify_field(multicast_metadata.mld_snooping_enabled, mld_snooping_enabled);
    modify_field(l3_metadata.rmac_group, rmac_group);
#ifdef SPLIT_HORIZON_CHECK_ENABLE
    modify_field(ig_intr_md_for_tm.level1_exclusion_id, exclusion_id);
#endif /* SPLIT_HORIZON_CHECK_ENABLE */
    modify_field(ig_intr_md_for_tm.rid, ingress_rid);
#ifdef VTEP_IFINDEX_ENABLE
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
#endif /* VTEP_IFINDEX_ENABLE */
}

table ingress_vni {
    reads {
        tunnel_metadata.tunnel_vni : exact;
    }
    actions {
      nop;
      set_ingress_vni_properties;
    }
    default_action : nop;
    size : VNID_MAPPING_TABLE_SIZE;
}

/* Adjust lookup fields for non-tunnel-termination case */
action ipv4_lkp() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(ipv4_metadata.lkp_ipv4_sa, ipv4.srcAddr);
    modify_field(ipv4_metadata.lkp_ipv4_da, ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_ttl, ipv4.ttl);
#if !defined(PARSER_EXTRACT_OUTER_ENABLE)
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_outer_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_outer_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_outer_tcp_flags);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
#ifndef TUNNEL_MULTICAST_DISABLE
    invalidate(ig_intr_md_for_tm.mcast_grp_a);
#endif /* TUNNEL_MULTICAST_DISABLE */
}

action ipv6_lkp() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(ipv6_metadata.lkp_ipv6_sa, ipv6.srcAddr);
    modify_field(ipv6_metadata.lkp_ipv6_da, ipv6.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl, ipv6.hopLimit);
    #if !defined(PARSER_EXTRACT_OUTER_ENABLE)
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_outer_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_outer_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, tcp.flags);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
#ifndef TUNNEL_MULTICAST_DISABLE
    invalidate(ig_intr_md_for_tm.mcast_grp_a);
#endif /* TUNNEL_MULTICAST_DISABLE */
}

action non_ip_lkp() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.non_ip_packet, TRUE);
#ifndef TUNNEL_MULTICAST_DISABLE
    invalidate(ig_intr_md_for_tm.mcast_grp_a);
#endif /* TUNNEL_MULTICAST_DISABLE */
}

table adjust_lkp_fields {
    reads {
        ipv4 : valid;
        ipv6 : valid;
    }
    actions {
        non_ip_lkp;
        ipv4_lkp;
#ifndef IPV6_DISABLE
        ipv6_lkp;
#endif /* IPV6_DISABLE */
    }
}

control process_tunnel_term {
    if (tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) {
        /* outer RMAC lookup for tunnel termination */
        apply(outer_rmac) {
            on_miss {
                apply(adjust_lkp_fields);
            }
            default {
                if (valid(ipv4)) {
#ifdef P2P_TUNNEL_TERM_ENABLE
                    apply(ipv4_vtep) {
                        nop {
                            apply(adjust_lkp_fields);
                        }
                    }
#else
                    apply(ipv4_src_vtep);
                    apply(ipv4_dest_vtep) {
                        nop {
                            apply(adjust_lkp_fields);
                        }
                    }
#endif /* P2P_TUNNEL_TERM_ENABLE */
#ifndef IPV6_TUNNEL_DISABLE
                } else {
                    if (valid(ipv6)) {
#ifdef P2P_TUNNEL_TERM_ENABLE
                        apply(ipv6_vtep) {
                            nop {
                                apply(adjust_lkp_fields);
                            }
                        }
#else
                        apply(ipv6_src_vtep);
                        apply(ipv6_dest_vtep) {
                            nop {
                                apply(adjust_lkp_fields);
                            }                                    
                        }
#endif /* P2P_TUNNEL_TERM_ENABLE */
                    }
#endif /* IPV6_TUNNEL_DISABLE */
                }
            }
        }
    } else {
        apply(adjust_lkp_fields);
    }
}
#else 
/*############################################################################/
/# Older Tunnel termination scheme                                           #/
/############################################################################*/

#ifndef TUNNEL_DISABLE
/*****************************************************************************/
/* IPv4 source and destination VTEP lookups                                  */
/*****************************************************************************/
action set_tunnel_lookup_flag(term_type) {
    modify_field(tunnel_metadata.tunnel_lookup, TRUE);
    modify_field(tunnel_metadata.tunnel_term_type, term_type);
}

action set_tunnel_vni_and_lookup_flag(tunnel_vni, term_type) {
    modify_field(tunnel_metadata.tunnel_vni, tunnel_vni);
    set_tunnel_lookup_flag(term_type);
}

action src_vtep_hit(ifindex) {
    modify_field(tunnel_metadata.src_vtep_hit, TRUE);
    modify_field(tunnel_metadata.vtep_ifindex, ifindex);
}

#ifdef MPLS_UDP_ENABLE
action remove_mpls_udp_ipv4_headers() {
    remove_header(udp);
    remove_header(ipv4);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
    set_valid_mpls_label();
    modify_field(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_MPLS);
}
#endif /* MPLS_UDP_ENABLE */

#ifndef IPV4_TUNNEL_DISABLE
table ipv4_dest_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv4.dstAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
    }
    actions {
        nop;
        set_tunnel_lookup_flag;
        set_tunnel_vni_and_lookup_flag;
#ifdef MPLS_UDP_ENABLE
        remove_mpls_udp_ipv4_headers;
#endif
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}

table ipv4_src_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv4.srcAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
    }
    actions {
        on_miss;
        src_vtep_hit;
    }
    size : IPV4_SRC_TUNNEL_TABLE_SIZE;
}
#endif /* IPV4_TUNNEL_DISABLE */


#ifndef IPV6_TUNNEL_DISABLE
/*****************************************************************************/
/* IPv6 source and destination VTEP lookups                                  */
/*****************************************************************************/
#ifdef MPLS_UDP_ENABLE
action remove_mpls_udp_ipv6_headers() {
    remove_header(udp);
    remove_header(ipv6);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
    set_valid_mpls_label();
    modify_field(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_MPLS);
}
#endif /* MPLS_UDP_ENABLE */

table ipv6_dest_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv6.dstAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
    }
    actions {
        nop;
        set_tunnel_lookup_flag;
        set_tunnel_vni_and_lookup_flag;
#ifdef MPLS_UDP_ENABLE
        remove_mpls_udp_ipv6_headers;
#endif
    }
    size : DEST_TUNNEL_TABLE_SIZE;
}

table ipv6_src_vtep {
    reads {
        l3_metadata.vrf : exact;
        ipv6.srcAddr : exact;
        tunnel_metadata.ingress_tunnel_type : exact;
    }
    actions {
        on_miss;
        src_vtep_hit;
    }
    size : IPV6_SRC_TUNNEL_TABLE_SIZE;
}
#endif /* IPV6_TUNNEL_DISABLE */

control process_ipv4_vtep {
#if !defined(IPV4_TUNNEL_DISABLE)
    apply(ipv4_src_vtep);
    apply(ipv4_dest_vtep);
#endif /* IPV4_TUNNEL_DISABLE */
}

control process_ipv6_vtep {
#if !defined(IPV6_TUNNEL_DISABLE)
    apply(ipv6_src_vtep);
    apply(ipv6_dest_vtep);
#endif /* !IPV6_TUNNEL_DISABLE */
}


#if !defined(MPLS_DISABLE)
/*****************************************************************************/
/* MPLS lookup/forwarding                                                    */
/*****************************************************************************/
action terminate_eompls(bd, tunnel_type) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(tunnel_metadata.ingress_tunnel_type, tunnel_type);
    modify_field(ingress_metadata.bd, bd);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_NONE);

    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
}

action terminate_vpls(bd, tunnel_type) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(tunnel_metadata.ingress_tunnel_type, tunnel_type);
    modify_field(ingress_metadata.bd, bd);

    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
}

#ifndef IPV4_DISABLE
action terminate_ipv4_over_mpls(vrf, tunnel_type) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(tunnel_metadata.ingress_tunnel_type, tunnel_type);
    modify_field(l3_metadata.vrf, vrf);

    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
#if defined(QOS_CLASSIFICATION_ENABLE) || defined(SS_QOS_CLASSIFICATION_ENABLE)
    modify_field(l3_metadata.lkp_dscp, inner_ipv4.diffserv);
#endif /* QOS_CLASSIFICATION_ENABLE || SS_QOS_CLASSIFICATION_ENABLE */
}
#endif /* IPV4_DISABLE */

#ifndef INNER_IPV6_DISABLE
action terminate_ipv6_over_mpls(vrf, tunnel_type) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(tunnel_metadata.ingress_tunnel_type, tunnel_type);
    modify_field(l3_metadata.vrf, vrf);

    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);
#if defined(QOS_CLASSIFICATION_ENABLE) || defined(SS_QOS_CLASSIFICATION_ENABLE)
    modify_field(l3_metadata.lkp_dscp, inner_ipv6.trafficClass);
#endif /* QOS_CLASSIFICATION_ENABLE || SS_QOS_CLASSIFICATION_ENABLE */
}
#endif /* INNER_IPV6_DISABLE */

action terminate_pw(ifindex) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);

    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
}

action forward_mpls(nexthop_index) {
    modify_field(l3_metadata.fib_nexthop, nexthop_index);
    modify_field(l3_metadata.fib_nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(l3_metadata.fib_hit, TRUE);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.non_ip_packet, TRUE);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}
#endif /* MPLS_DISABLE */

/*****************************************************************************/
/* Tunnel termination                                                        */
/*****************************************************************************/
action terminate_tunnel_inner_non_ip(bd, bd_label, stats_idx,
                                     exclusion_id, ingress_rid) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(ingress_metadata.bd, bd);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_NONE);
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);

#ifdef SPLIT_HORIZON_CHECK_ENABLE
    modify_field(ig_intr_md_for_tm.level1_exclusion_id, exclusion_id);
#endif /* SPLIT_HORIZON_CHECK_ENABLE */
    modify_field(ig_intr_md_for_tm.rid, ingress_rid);

    modify_field(l2_metadata.non_ip_packet, TRUE);
}

#ifndef IPV4_DISABLE
action terminate_tunnel_inner_ethernet_ipv4(bd, vrf,
        rmac_group, bd_label,
        ipv4_unicast_enabled, ipv4_urpf_mode,
        igmp_snooping_enabled, stats_idx,
        ipv4_multicast_enabled, mrpf_group,
        exclusion_id, ingress_rid) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(ingress_metadata.bd, bd);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
#if !defined(URPF_DISABLE)
    modify_field(ipv4_metadata.ipv4_urpf_mode, ipv4_urpf_mode);
#endif /* URPF_DISABLE */
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
#if defined(QOS_CLASSIFICATION_ENABLE) || defined(SS_QOS_CLASSIFICATION_ENABLE)
    modify_field(l3_metadata.lkp_dscp, inner_ipv4.diffserv);
#endif /* QOS_CLASSIFICATION_ENABLE || SS_QOS_CLASSIFICATION_ENABLE */

    modify_field(multicast_metadata.igmp_snooping_enabled,
                 igmp_snooping_enabled);
    modify_field(multicast_metadata.ipv4_multicast_enabled,
                 ipv4_multicast_enabled);
    modify_field(multicast_metadata.bd_mrpf_group, mrpf_group);

#ifdef SPLIT_HORIZON_CHECK_ENABLE
    modify_field(ig_intr_md_for_tm.level1_exclusion_id, exclusion_id);
#endif /* SPLIT_HORIZON_CHECK_ENABLE */
    modify_field(ig_intr_md_for_tm.rid, ingress_rid);
}

action terminate_tunnel_inner_ipv4(vrf, rmac_group,
        ipv4_urpf_mode, ipv4_unicast_enabled,
        ipv4_multicast_enabled, mrpf_group) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
#if !defined(URPF_DISABLE)
    modify_field(ipv4_metadata.ipv4_urpf_mode, ipv4_urpf_mode);
#endif /* URPF_DISABLE */
    modify_field(l3_metadata.rmac_group, rmac_group);

    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv4.version);
#if defined(QOS_CLASSIFICATION_ENABLE) || defined(SS_QOS_CLASSIFICATION_ENABLE)
    modify_field(l3_metadata.lkp_dscp, inner_ipv4.diffserv);
#endif /* QOS_CLASSIFICATION_ENABLE || SS_QOS_CLASSIFICATION_ENABLE */

    modify_field(multicast_metadata.bd_mrpf_group, mrpf_group);
    modify_field(multicast_metadata.ipv4_multicast_enabled,
                 ipv4_multicast_enabled);
}
#endif /* IPV4_DISABLE */

#ifndef INNER_IPV6_DISABLE
action terminate_tunnel_inner_ethernet_ipv6(bd, vrf,
        rmac_group, bd_label,
        ipv6_unicast_enabled, ipv6_urpf_mode,
        mld_snooping_enabled, stats_idx,
        ipv6_multicast_enabled, mrpf_group,
        exclusion_id, ingress_rid) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(ingress_metadata.bd, bd);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
#if !defined(URPF_DISABLE)
    modify_field(ipv6_metadata.ipv6_urpf_mode, ipv6_urpf_mode);
#endif /* URPF_DISABLE */
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);

    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l2_metadata.lkp_mac_type, inner_ethernet.etherType);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);

#if defined(QOS_CLASSIFICATION_ENABLE) || defined(SS_QOS_CLASSIFICATION_ENABLE)
    modify_field(l3_metadata.lkp_dscp, inner_ipv6.trafficClass);
#endif /* QOS_CLASSIFICATION_ENABLE || SS_QOS_CLASSIFICATION_ENABLE */

    modify_field(multicast_metadata.bd_mrpf_group, mrpf_group);
    modify_field(multicast_metadata.ipv6_multicast_enabled,
                 ipv6_multicast_enabled);
    modify_field(multicast_metadata.mld_snooping_enabled, mld_snooping_enabled);

#ifdef SPLIT_HORIZON_CHECK_ENABLE
    modify_field(ig_intr_md_for_tm.level1_exclusion_id, exclusion_id);
#endif /* SPLIT_HORIZON_CHECK_ENABLE */
    modify_field(ig_intr_md_for_tm.rid, ingress_rid);
}

action terminate_tunnel_inner_ipv6(vrf, rmac_group,
        ipv6_unicast_enabled, ipv6_urpf_mode,
        ipv6_multicast_enabled, mrpf_group) {
    modify_field(tunnel_metadata.tunnel_terminate, TRUE);
    modify_field(ingress_metadata.ifindex, tunnel_metadata.vtep_ifindex);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
#if !defined(URPF_DISABLE)
    modify_field(ipv6_metadata.ipv6_urpf_mode, ipv6_urpf_mode);
#endif /* URPF_DISABLE */
    modify_field(l3_metadata.rmac_group, rmac_group);

    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l3_metadata.lkp_ip_version, inner_ipv6.version);

#if defined(QOS_CLASSIFICATION_ENABLE) || defined(SS_QOS_CLASSIFICATION_ENABLE)
    modify_field(l3_metadata.lkp_dscp, inner_ipv6.trafficClass);
#endif /* QOS_CLASSIFICATION_ENABLE || SS_QOS_CLASSIFICATION_ENABLE */

    modify_field(multicast_metadata.bd_mrpf_group, mrpf_group);
    modify_field(multicast_metadata.ipv6_multicast_enabled,
                 ipv6_multicast_enabled);
}
#endif /* INNER_IPV6_DISABLE */

action tunnel_lookup_miss() {
}

table tunnel {
    reads {
        tunnel_metadata.tunnel_vni : exact;
        mpls[0] : valid;
        inner_ipv4 : valid;
        inner_ipv6 : valid;
    }
    actions {
        nop;
        tunnel_lookup_miss;
        terminate_tunnel_inner_non_ip;
#ifndef IPV4_DISABLE
        terminate_tunnel_inner_ethernet_ipv4;
        terminate_tunnel_inner_ipv4;
#endif /* IPV4_DISABLE */
#ifndef INNER_IPV6_DISABLE
        terminate_tunnel_inner_ethernet_ipv6;
        terminate_tunnel_inner_ipv6;
#endif /* INNER_IPV6_DISABLE */
#ifndef MPLS_DISABLE
        terminate_eompls;
        terminate_vpls;
#ifndef IPV4_DISABLE
        terminate_ipv4_over_mpls;
#endif /* IPV4_DISABLE */
#ifndef INNER_IPV6_DISABLE
        terminate_ipv6_over_mpls;
#endif /* INNER_IPV6_DISABLE */
        terminate_pw;
        forward_mpls;
#endif /* MPLS_DISABLE */
    }
    size : VNID_MAPPING_TABLE_SIZE;
}
#endif /* TUNNEL_DISABLE */

action ipv4_lkp() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(ipv4_metadata.lkp_ipv4_sa, ipv4.srcAddr);
    modify_field(ipv4_metadata.lkp_ipv4_da, ipv4.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_ttl, ipv4.ttl);
#if !defined(PARSER_EXTRACT_OUTER_ENABLE)
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_outer_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_outer_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, l3_metadata.lkp_outer_tcp_flags);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
#ifndef TUNNEL_MULTICAST_DISABLE
    invalidate(ig_intr_md_for_tm.mcast_grp_a);
#endif /* TUNNEL_MULTICAST_DISABLE */
#ifdef SRV6_L3VPN_PROFILE
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l2_metadata.lkp_mac_type, ETHERTYPE_IPV4);
#endif /* SRV6_L3VPN_PROFILE */    
}

action ipv6_lkp() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(ipv6_metadata.lkp_ipv6_sa, ipv6.srcAddr);
    modify_field(ipv6_metadata.lkp_ipv6_da, ipv6.dstAddr);
    modify_field(l3_metadata.lkp_ip_proto, ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl, ipv6.hopLimit);
#if !defined(PARSER_EXTRACT_OUTER_ENABLE)
    modify_field(l3_metadata.lkp_l4_sport, l3_metadata.lkp_outer_l4_sport);
    modify_field(l3_metadata.lkp_l4_dport, l3_metadata.lkp_outer_l4_dport);
    modify_field(l3_metadata.lkp_tcp_flags, tcp.flags);
#endif /* PARSER_EXTRACT_OUTER_ENABLE */
#ifndef TUNNEL_MULTICAST_DISABLE
    invalidate(ig_intr_md_for_tm.mcast_grp_a);
#endif /* TUNNEL_MULTICAST_DISABLE */
#ifdef SRV6_L3VPN_PROFILE
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l2_metadata.lkp_mac_type, ETHERTYPE_IPV6);
#endif /* SRV6_L3VPN_PROFILE */    
}

action non_ip_lkp() {
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
    modify_field(l2_metadata.non_ip_packet, TRUE);
#ifndef TUNNEL_MULTICAST_DISABLE
    invalidate(ig_intr_md_for_tm.mcast_grp_a);
#endif /* TUNNEL_MULTICAST_DISABLE */
#ifdef SRV6_L3VPN_PROFILE
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_NONE);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
#endif /* SRV6_L3VPN_PROFILE */    
}

#ifdef GENERIC_INT_LEAF_PROFILE
@pragma ternary 1
#endif
table adjust_lkp_fields {
    reads {
        ipv4 : valid;
        ipv6 : valid;
    }
    actions {
        non_ip_lkp;
        ipv4_lkp;
#ifndef IPV6_DISABLE
        ipv6_lkp;
#endif /* IPV6_DISABLE */
    }
}

table tunnel_lookup_miss {
    reads {
        ipv4 : valid;
        ipv6 : valid;
    }
    actions {
        non_ip_lkp;
        ipv4_lkp;
#ifndef IPV6_DISABLE
        ipv6_lkp;
#endif /* IPV6_DISABLE */
    }
}

action tunnel_check_pass() {
}

table tunnel_check {
    reads {
        tunnel_metadata.ingress_tunnel_type : ternary;
        tunnel_metadata.tunnel_lookup : ternary;
        tunnel_metadata.src_vtep_hit : ternary;
        tunnel_metadata.tunnel_term_type : ternary;
    }
    actions {
        nop;
        tunnel_check_pass;
    }
}

/*****************************************************************************/
/* Ingress tunnel processing                                                 */
/*****************************************************************************/
control process_tunnel {
#ifndef TUNNEL_DISABLE
    if (tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) {

        /* outer RMAC lookup for tunnel termination */
        apply(outer_rmac) {
            on_miss {
#if !defined(TUNNEL_MULTICAST_DISABLE)
                process_outer_multicast();
#endif /* !TUNNEL_MULTICAST_DISABLE */
            }
            default {
                if (valid(ipv4)) {
                    process_ipv4_vtep();
                } else {
                    if (valid(ipv6)) {
                        process_ipv6_vtep();
                    }
                }
            }
        }
    }

    /* perform tunnel termination */
    if ((tunnel_metadata.tunnel_lookup == TRUE)
#if !defined(TUNNEL_MULTICAST_DISABLE)
        or ((multicast_metadata.outer_mcast_route_hit == TRUE) and
	    (((multicast_metadata.outer_mcast_mode == MCAST_MODE_SM) and
	      (multicast_metadata.mcast_rpf_group == 0)) or
	     ((multicast_metadata.outer_mcast_mode == MCAST_MODE_BIDIR) and
	      (multicast_metadata.mcast_rpf_group != 0))))
#endif /* TUNNEL_MULTICAST_DISABLE */
	) {
        apply(tunnel_check) {
            tunnel_check_pass {
                apply(tunnel) {
                    tunnel_lookup_miss {
                        apply(tunnel_lookup_miss);
                    }
                }
            }
        }
    } else {
        apply(adjust_lkp_fields);
    }
#endif /* TUNNEL_DISABLE */
}

#if !defined(MPLS_DISABLE)
/*****************************************************************************/
/* Validate MPLS header                                                      */
/*****************************************************************************/
field_list mpls_fields {
    mpls[0].label;
}

field_list_calculation mpls_field_list {
    input {
        mpls_fields;
    }
    algorithm : identity;
    output_width : 20;
}

action set_valid_mpls_label() {
#if !defined(__TARGET_TOFINO__) || defined(BMV2TOFINO)
    modify_field(tunnel_metadata.tunnel_vni, mpls[0].label);
#else
    modify_field_with_hash_based_offset(tunnel_metadata.tunnel_vni, 0,
                                        mpls_field_list, 16777216);
#endif
    modify_field(tunnel_metadata.mpls_exp, mpls[0].exp);
    modify_field(tunnel_metadata.tunnel_lookup, TRUE);
}

action set_valid_mpls_udp_label() {
    modify_field(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_MPLS_IN_UDP);
}

@pragma immediate 0
table validate_mpls_packet {
    reads {
        mpls[0] : valid;
#if defined(MPLS_UDP_ENABLE)
        tunnel_metadata.mpls_in_udp : exact;
#endif
    }
    actions {
        set_valid_mpls_label;
#if defined(MPLS_UDP_ENABLE)
        set_valid_mpls_udp_label;
#endif
    }
    size : VALIDATE_MPLS_TABLE_SIZE;
}
#endif /* MPLS_DISABLE */

control validate_mpls_header {
#if !defined(MPLS_DISABLE)
    apply(validate_mpls_packet);
#endif /* MPLS_DISABLE */
}

#endif /* ALT_TUNNEL_TERM_ENABLE */

#ifndef TUNNEL_DISABLE
/*****************************************************************************/
/* Tunnel decap (strip tunnel header)                                        */
/*****************************************************************************/
action decap_vxlan_inner_ipv4() {
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv4, inner_ipv4);
    remove_header(vxlan);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
}

#ifndef INNER_IPV6_DISABLE
action decap_vxlan_inner_ipv6() {
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv6, inner_ipv6);
    remove_header(vxlan);
    remove_header(ipv4);
    remove_header(inner_ethernet);
    remove_header(inner_ipv6);
}
#endif /* INNER_IPV6_DISABLE */

action decap_vxlan_inner_non_ip() {
    copy_header(ethernet, inner_ethernet);
    remove_header(vxlan);
    remove_header(ipv4);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ethernet);
}

#ifndef GENEVE_DISABLE
action decap_genv_inner_ipv4() {
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv4, inner_ipv4);
    remove_header(genv);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
}

action decap_genv_inner_ipv6() {
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv6, inner_ipv6);
    remove_header(genv);
    remove_header(ipv4);
    remove_header(inner_ethernet);
    remove_header(inner_ipv6);
}

action decap_genv_inner_non_ip() {
    copy_header(ethernet, inner_ethernet);
    remove_header(genv);
    remove_header(ipv4);
#ifndef IPV6_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ethernet);
}
#endif /* GENEVE_DISABLE */

#ifndef NVGRE_DISABLE
action decap_nvgre_inner_ipv4() {
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv4, inner_ipv4);
    remove_header(nvgre);
    remove_header(gre);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
}

action decap_nvgre_inner_ipv6() {
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv6, inner_ipv6);
    remove_header(nvgre);
    remove_header(gre);
    remove_header(ipv4);
    remove_header(inner_ethernet);
    remove_header(inner_ipv6);
}

action decap_nvgre_inner_non_ip() {
    copy_header(ethernet, inner_ethernet);
    remove_header(nvgre);
    remove_header(gre);
    remove_header(ipv4);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ethernet);
}
#endif

action decap_gre_inner_ipv4() {
    copy_header(ipv4, inner_ipv4);
    remove_header(gre);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ipv4);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef INNER_IPV6_DISABLE
action decap_gre_inner_ipv6() {
    copy_header(ipv6, inner_ipv6);
    remove_header(gre);
    remove_header(ipv4);
    remove_header(inner_ipv6);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* INNER_IPV6_DISABLE */

action decap_gre_inner_non_ip() {
    modify_field(ethernet.etherType, gre.proto);
    remove_header(gre);
    remove_header(ipv4);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
}

//action decap_ip_inner_ethernet() {
//    modify_field(ethernet.etherType, ipv6.nextHdr);
//    copy_header(ethernet, inner_ethernet);
//#ifndef IPV6_TUNNEL_DISABLE
//    remove_header(ipv6);
//#endif
//    remove_header(inner_ethernet);
//}

action decap_ip_inner_ipv4() {
    copy_header(ipv4, inner_ipv4);
#ifndef IPV6_TUNNEL_DISABLE
    remove_header(ipv6);
#endif
    remove_header(inner_ipv4);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef INNER_IPV6_DISABLE
action decap_ip_inner_ipv6() {
    copy_header(ipv6, inner_ipv6);
    remove_header(ipv4);
    remove_header(inner_ipv6);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* INNER_IPV6_DISABLE */

#ifndef MPLS_DISABLE
action decap_mpls_inner_ipv4_pop1() {
    remove_header(mpls[0]);
    copy_header(ipv4, inner_ipv4);
    remove_header(inner_ipv4);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

action decap_mpls_inner_ipv4_pop2() {
    remove_header(mpls[1]);
    decap_mpls_inner_ipv4_pop1();
}

action decap_mpls_inner_ipv4_pop3() {
    remove_header(mpls[2]);
    decap_mpls_inner_ipv4_pop2();
}

action decap_mpls_inner_ipv6_pop1() {
    remove_header(mpls[0]);
    copy_header(ipv6, inner_ipv6);
    remove_header(inner_ipv6);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}

action decap_mpls_inner_ipv6_pop2() {
    remove_header(mpls[1]);
    decap_mpls_inner_ipv6_pop1();
}

action decap_mpls_inner_ipv6_pop3() {
    remove_header(mpls[2]);
    decap_mpls_inner_ipv6_pop2();
}

action decap_mpls_inner_ethernet_ipv4_pop1() {
    remove_header(mpls[0]);
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv4, inner_ipv4);
    remove_header(inner_ethernet);
    remove_header(inner_ipv4);
}

action decap_mpls_inner_ethernet_ipv4_pop2() {
    remove_header(mpls[1]);
    decap_mpls_inner_ethernet_ipv4_pop1();
}

action decap_mpls_inner_ethernet_ipv4_pop3() {
    remove_header(mpls[2]);
    decap_mpls_inner_ethernet_ipv4_pop2();
}

action decap_mpls_inner_ethernet_ipv6_pop1() {
    remove_header(mpls[0]);
    copy_header(ethernet, inner_ethernet);
    copy_header(ipv6, inner_ipv6);
    remove_header(inner_ipv6);
    remove_header(inner_ethernet);
}

action decap_mpls_inner_ethernet_ipv6_pop2() {
    remove_header(mpls[1]);
    decap_mpls_inner_ethernet_ipv6_pop1();
}

action decap_mpls_inner_ethernet_ipv6_pop3() {
    remove_header(mpls[2]);
    decap_mpls_inner_ethernet_ipv6_pop2();
}


action decap_mpls_inner_ethernet_non_ip_pop1() {
    remove_header(mpls[0]);
    copy_header(ethernet, inner_ethernet);
    remove_header(inner_ethernet);
}

action decap_mpls_inner_ethernet_non_ip_pop2() {
    remove_header(mpls[1]);
    decap_mpls_inner_ethernet_non_ip_pop1();
}

action decap_mpls_inner_ethernet_non_ip_pop3() {
    remove_header(mpls[2]);
    decap_mpls_inner_ethernet_non_ip_pop2();
}

#endif /* MPLS_DISABLE */

table tunnel_decap_process_outer {
    reads {
        tunnel_metadata.ingress_tunnel_type : exact;
        inner_ipv4 : valid;
        inner_ipv6 : valid;
    }
    actions {
        decap_vxlan_inner_ipv4;
        decap_vxlan_inner_non_ip;
#ifndef GENEVE_DISABLE
        decap_genv_inner_ipv4;
        decap_genv_inner_non_ip;
#endif /* GENEVE_DISABLE */
        decap_gre_inner_ipv4;
        decap_gre_inner_non_ip;
        decap_ip_inner_ipv4;
//        decap_ip_inner_ethernet;

#ifdef SRV6_ENABLE
        // decap_ip_inner_ipv4/ipv6/ethernet are used for SRv6 L3/L2VPN termination
//        decap_sr_inner_non_ip;
//        decap_sr_inner_ipv4;
//        decap_sr_inner_ipv6;
#endif /* SRV6_ENABLE */

#if !defined(INNER_IPV6_DISABLE)
        decap_vxlan_inner_ipv6;
#ifndef GENEVE_DISABLE
        decap_genv_inner_ipv6;
#endif /* GENEVE_DISABLE */
        decap_gre_inner_ipv6;
        decap_ip_inner_ipv6;
#endif /* INNER_IPV6_DISABLE */

#ifndef NVGRE_DISABLE
        decap_nvgre_inner_ipv4;
        decap_nvgre_inner_non_ip;
#if !defined(INNER_IPV6_DISABLE)
        decap_nvgre_inner_ipv6;
#endif /* INNER_IPV6_DISABLE */
#endif
#ifndef MPLS_DISABLE
        decap_mpls_inner_ipv4_pop1;
        decap_mpls_inner_ethernet_ipv4_pop1;
        decap_mpls_inner_ethernet_non_ip_pop1;
        decap_mpls_inner_ipv4_pop2;
        decap_mpls_inner_ethernet_ipv4_pop2;
        decap_mpls_inner_ethernet_non_ip_pop2;
        decap_mpls_inner_ipv4_pop3;
        decap_mpls_inner_ethernet_ipv4_pop3;
        decap_mpls_inner_ethernet_non_ip_pop3;
#ifndef IPV6_DISABLE
        decap_mpls_inner_ipv6_pop1;
        decap_mpls_inner_ethernet_ipv6_pop1;
        decap_mpls_inner_ipv6_pop2;
        decap_mpls_inner_ethernet_ipv6_pop2;
        decap_mpls_inner_ipv6_pop3;
        decap_mpls_inner_ethernet_ipv6_pop3;
#endif
#endif /* MPLS_DISABLE */
    }
    size : TUNNEL_DECAP_TABLE_SIZE;
}

/*****************************************************************************/
/* Tunnel decap (move inner header to outer)                                 */
/*****************************************************************************/
action decap_inner_udp() {
    modify_field(l3_metadata.lkp_l4_sport, inner_udp.srcPort);
    modify_field(l3_metadata.lkp_l4_dport, inner_udp.dstPort);
    copy_header(udp, inner_udp);
    remove_header(inner_udp);
}

action decap_inner_tcp() {
    modify_field(l3_metadata.lkp_l4_sport, inner_tcp.srcPort);
    modify_field(l3_metadata.lkp_l4_dport, inner_tcp.dstPort);
    copy_tcp_header(tcp, inner_tcp);
    remove_header(inner_tcp);
    remove_header(udp);
}

action decap_inner_icmp() {
    modify_field(l3_metadata.lkp_l4_sport, inner_icmp.typeCode);
    copy_header(icmp, inner_icmp);
    remove_header(inner_icmp);
    remove_header(udp);
}

action decap_inner_unknown() {
    remove_header(udp);
}

table tunnel_decap_process_inner {
    reads {
        inner_tcp : valid;
        inner_udp : valid;
        inner_icmp : valid;
    }
    actions {
        decap_inner_udp;
        decap_inner_tcp;
        decap_inner_icmp;
        decap_inner_unknown;
    }
    size : TUNNEL_DECAP_TABLE_SIZE;
}
#endif /* TUNNEL_DISABLE */


/*****************************************************************************/
/* Tunnel decap processing                                                   */
/*****************************************************************************/
control process_tunnel_decap {
#ifndef TUNNEL_DISABLE
    if (tunnel_metadata.tunnel_terminate == TRUE) {
#ifndef TUNNEL_MULTICAST_DISABLE        
        if ((multicast_metadata.inner_replica == TRUE) or
            (multicast_metadata.replica == FALSE)) {
#endif /* TUNNEL_MULTICAST_DISABLE */           
#ifdef __p4c__
            apply(tunnel_decap_process_outer) {
                default { apply(tunnel_decap_process_inner); }
            }
#else
            apply(tunnel_decap_process_outer);
            apply(tunnel_decap_process_inner);
#endif
#ifndef TUNNEL_MULTICAST_DISABLE        
        }
#endif /* TUNNEL_MULTICAST_DISABLE */           
    }
#endif /* TUNNEL_DISABLE */
}


#ifndef TUNNEL_DISABLE
/*****************************************************************************/
/* Egress tunnel VNI lookup                                                  */
/*****************************************************************************/
action set_egress_tunnel_vni(vnid) {
    modify_field(tunnel_metadata.vnid, vnid);
}

table egress_vni {
    reads {
        egress_metadata.bd : exact;
    }
    actions {
        set_egress_tunnel_vni;
    }
    default_action : set_egress_tunnel_vni(0);
    size: EGRESS_VNID_MAPPING_TABLE_SIZE;
}
#endif /* TUNNEL_DISABLE */

#if !defined(TUNNEL_DISABLE)
/*****************************************************************************/
/* Tunnel encap (inner header rewrite)                                       */
/*****************************************************************************/
action inner_ipv4_udp_rewrite() {
    copy_header(inner_ipv4, ipv4);
    copy_header(inner_udp, udp);
    modify_field(egress_metadata.payload_length, ipv4.totalLen);
    remove_header(udp);
    remove_header(ipv4);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV4);
}

action inner_ipv4_tcp_rewrite() {
    copy_header(inner_ipv4, ipv4);
    copy_tcp_header(inner_tcp, tcp);
    modify_field(egress_metadata.payload_length, ipv4.totalLen);
    remove_header(tcp);
    remove_header(ipv4);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV4);
}

action inner_ipv4_icmp_rewrite() {
    copy_header(inner_ipv4, ipv4);
    copy_header(inner_icmp, icmp);
    modify_field(egress_metadata.payload_length, ipv4.totalLen);
    remove_header(icmp);
    remove_header(ipv4);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV4);
}

action inner_ipv4_unknown_rewrite() {
    copy_header(inner_ipv4, ipv4);
    modify_field(egress_metadata.payload_length, ipv4.totalLen);
    remove_header(ipv4);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV4);
}

#ifndef INNER_IPV6_DISABLE
action inner_ipv6_udp_rewrite() {
    copy_header(inner_ipv6, ipv6);
    copy_header(inner_udp, udp);
    add(egress_metadata.payload_length, ipv6.payloadLen, 40);
    remove_header(ipv6);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV6);
}

action inner_ipv6_tcp_rewrite() {
    copy_header(inner_ipv6, ipv6);
    copy_tcp_header(inner_tcp, tcp);
    add(egress_metadata.payload_length, ipv6.payloadLen, 40);
    remove_header(tcp);
    remove_header(ipv6);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV6);
}

action inner_ipv6_icmp_rewrite() {
    copy_header(inner_ipv6, ipv6);
    copy_header(inner_icmp, icmp);
    add(egress_metadata.payload_length, ipv6.payloadLen, 40);
    remove_header(icmp);
    remove_header(ipv6);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV6);
}

action inner_ipv6_unknown_rewrite() {
    copy_header(inner_ipv6, ipv6);
    add(egress_metadata.payload_length, ipv6.payloadLen, 40);
    remove_header(ipv6);
    modify_field(tunnel_metadata.inner_ip_proto, IP_PROTOCOLS_IPV6);
}
#endif /* INNER_IPV6_DISABLE */

action inner_non_ip_rewrite() {
#ifndef __TARGET_TOFINO__
    add(egress_metadata.payload_length, standard_metadata.packet_length, -14);
#else
    add(egress_metadata.payload_length, eg_intr_md.pkt_length, -14);
#endif /* __TARGET_TOFINO__ */
}

@pragma ternary 1
table tunnel_encap_process_inner {
    reads {
        ipv4 : valid;
        ipv6 : valid;
        tcp : valid;
        udp : valid;
        icmp : valid;
    }
    actions {
        inner_ipv4_udp_rewrite;
        inner_ipv4_tcp_rewrite;
        inner_ipv4_icmp_rewrite;
        inner_ipv4_unknown_rewrite;
#ifndef INNER_IPV6_DISABLE
        inner_ipv6_udp_rewrite;
        inner_ipv6_tcp_rewrite;
        inner_ipv6_icmp_rewrite;
        inner_ipv6_unknown_rewrite;
#endif
        inner_non_ip_rewrite;
    }
    size : TUNNEL_HEADER_TABLE_SIZE;
}
#endif /* !TUNNEL_DISABLE */


#ifndef TUNNEL_DISABLE
/*****************************************************************************/
/* Tunnel encap (insert tunnel header)                                       */
/*****************************************************************************/
action f_insert_vxlan_header(udp_dst_port) {
    copy_header(inner_ethernet, ethernet);
    add_header(udp);
    add_header(vxlan);

    modify_field(udp.srcPort, hash_metadata.entropy_hash);
    modify_field(udp.dstPort, udp_dst_port);
    modify_field(udp.checksum, 0);
    add(udp.length_, egress_metadata.payload_length, 30);

    modify_field(vxlan.flags, 0x8);
    modify_field(vxlan.reserved, 0);
    modify_field(vxlan.vni, tunnel_metadata.vnid);
    modify_field(vxlan.reserved2, 0);
}

action ipv4_vxlan_rewrite(udp_dst_port) {
    f_insert_vxlan_header(udp_dst_port);
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    add(ipv4.totalLen, egress_metadata.payload_length, 50);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef IPV6_TUNNEL_DISABLE
action ipv6_vxlan_rewrite(udp_dst_port) {
    f_insert_vxlan_header(udp_dst_port);
    f_insert_ipv6_header(IP_PROTOCOLS_UDP);
    add(ipv6.payloadLen, egress_metadata.payload_length, 30);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* IPV6_TUNNEL_DISABLE */

#ifndef GENEVE_DISABLE
action f_insert_genv_header() {
    copy_header(inner_ethernet, ethernet);
    add_header(udp);
    add_header(genv);

    modify_field(udp.srcPort, hash_metadata.entropy_hash);
    modify_field(udp.dstPort, UDP_PORT_GENV);
    modify_field(udp.checksum, 0);
    add(udp.length_, egress_metadata.payload_length, 30);

    modify_field(genv.ver, 0);
    modify_field(genv.oam, 0);
    modify_field(genv.critical, 0);
    modify_field(genv.optLen, 0);
    modify_field(genv.protoType, ETHERTYPE_ETHERNET);
    modify_field(genv.vni, tunnel_metadata.vnid);
    modify_field(genv.reserved, 0);
    modify_field(genv.reserved2, 0);
}

action ipv4_genv_rewrite() {
    f_insert_genv_header();
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    add(ipv4.totalLen, egress_metadata.payload_length, 50);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef IPV6_TUNNEL_DISABLE
action ipv6_genv_rewrite() {
    f_insert_genv_header();
    f_insert_ipv6_header(IP_PROTOCOLS_UDP);
    add(ipv6.payloadLen, egress_metadata.payload_length, 30);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* IPV6_TUNNEL_DISABLE */
#endif /* GENEVE_DISABLE */

#ifndef NVGRE_DISABLE
action f_insert_nvgre_header() {
    copy_header(inner_ethernet, ethernet);
    add_header(gre);
    add_header(nvgre);
    modify_field(gre.proto, ETHERTYPE_ETHERNET);
    modify_field(gre.recurse, 0);
    modify_field(gre.flags, 0);
    modify_field(gre.ver, 0);
    modify_field(gre.R, 0);
    modify_field(gre.K, 1);
    modify_field(gre.C, 0);
    modify_field(gre.S, 0);
    modify_field(gre.s, 0);
    modify_field(nvgre.tni, tunnel_metadata.vnid);
    modify_field(nvgre.flow_id, hash_metadata.entropy_hash, 0xFF);
}

action ipv4_nvgre_rewrite() {
    f_insert_nvgre_header();
    f_insert_ipv4_header(IP_PROTOCOLS_GRE);
    add(ipv4.totalLen, egress_metadata.payload_length, 42);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef IPV6_TUNNEL_DISABLE
action ipv6_nvgre_rewrite() {
    f_insert_nvgre_header();
    f_insert_ipv6_header(IP_PROTOCOLS_GRE);
    add(ipv6.payloadLen, egress_metadata.payload_length, 22);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* IPV6_TUNNEL_DISABLE */
#endif

action f_insert_gre_header() {
    add_header(gre);
}

action ipv4_gre_rewrite() {
    f_insert_gre_header();
    modify_field(gre.proto, ethernet.etherType);
    f_insert_ipv4_header(IP_PROTOCOLS_GRE);
    add(ipv4.totalLen, egress_metadata.payload_length, 24);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef IPV6_TUNNEL_DISABLE
action ipv6_gre_rewrite() {
    f_insert_gre_header();
    modify_field(gre.proto, ethernet.etherType);
    f_insert_ipv6_header(IP_PROTOCOLS_GRE);
    add(ipv6.payloadLen, egress_metadata.payload_length, 4);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* IPV6_TUNNEL_DISABLE */

action ipv4_ip_rewrite() {
    f_insert_ipv4_header(tunnel_metadata.inner_ip_proto);
    add(ipv4.totalLen, egress_metadata.payload_length, 20);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
}

#ifndef IPV6_TUNNEL_DISABLE
action ipv6_ip_rewrite() {
    f_insert_ipv6_header(tunnel_metadata.inner_ip_proto);
    modify_field(ipv6.payloadLen, egress_metadata.payload_length);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}
#endif /* IPV6_TUNNEL_DISABLE */

#ifndef MPLS_DISABLE
action mpls_ethernet_push1_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 1);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}

action mpls_ip_push1_rewrite() {
    push(mpls, 1);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}

action mpls_ethernet_push2_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 2);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}

action mpls_ip_push2_rewrite() {
    push(mpls, 2);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}

action mpls_ethernet_push3_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 3);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}

action mpls_ip_push3_rewrite() {
    push(mpls, 3);
    modify_field(ethernet.etherType, ETHERTYPE_MPLS);
}

action f_insert_mpls_udp_header() {
    add_header(udp);
    modify_field(udp.srcPort, hash_metadata.entropy_hash);
    modify_field(udp.checksum, 0);
    modify_field(udp.dstPort, UDP_PORT_MPLS);
}

action f_insert_mpls_ipv4_udp() {
    f_insert_ipv4_header(IP_PROTOCOLS_UDP);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
    f_insert_mpls_udp_header();
}

#ifndef IPV6_TUNNEL_DISABLE
action f_insert_mpls_ipv6_udp() {
    f_insert_ipv6_header(IP_PROTOCOLS_UDP);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
    f_insert_mpls_udp_header();
}
#endif /* IPV6_TUNNEL_DISABLE */

action mpls_ipv4_udp_push_rewrite() {
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 8);
    add(ipv4.totalLen, egress_metadata.payload_length, 28);
}

action mpls_ipv4_udp_ethernet_push1_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 1);
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 26);
    add(ipv4.totalLen, egress_metadata.payload_length, 46);
}

action mpls_ipv4_udp_ip_push1_rewrite() {
    push(mpls, 1);
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 12);
    add(ipv4.totalLen, egress_metadata.payload_length, 32);
}

action mpls_ipv4_udp_ethernet_push2_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 2);
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 30);
    add(ipv4.totalLen, egress_metadata.payload_length, 50);
}

action mpls_ipv4_udp_ip_push2_rewrite() {
    push(mpls, 2);
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 16);
    add(ipv4.totalLen, egress_metadata.payload_length, 36);
}

action mpls_ipv4_udp_ethernet_push3_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 3);
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 34);
    add(ipv4.totalLen, egress_metadata.payload_length, 54);
}

action mpls_ipv4_udp_ip_push3_rewrite() {
    push(mpls, 3);
    f_insert_mpls_ipv4_udp();
    add(udp.length_, egress_metadata.payload_length, 20);
    add(ipv4.totalLen, egress_metadata.payload_length, 40);
}

#ifndef IPV6_TUNNEL_DISABLE
action mpls_ipv6_udp_push_rewrite() {
    f_insert_mpls_ipv6_udp();
    add(ipv6.payloadLen, egress_metadata.payload_length, 8);
    add(udp.length_, egress_metadata.payload_length, 8);
}

action mpls_ipv6_udp_ethernet_push1_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 1);
    f_insert_mpls_ipv6_udp();
    add(udp.length_, egress_metadata.payload_length, 26);
    add(ipv6.payloadLen, egress_metadata.payload_length, 26);
}

action mpls_ipv6_udp_ip_push1_rewrite() {
    push(mpls, 1);
    f_insert_mpls_ipv6_udp();
    add(udp.length_, egress_metadata.payload_length, 12);
    add(ipv6.payloadLen, egress_metadata.payload_length, 12);
}

action mpls_ipv6_udp_ethernet_push2_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 2);
    f_insert_mpls_ipv6_udp();
    add(udp.length_, egress_metadata.payload_length, 30);
    add(ipv6.payloadLen, egress_metadata.payload_length, 30);
}

action mpls_ipv6_udp_ip_push2_rewrite() {
    push(mpls, 2);
    f_insert_mpls_ipv6_udp();
    add(udp.length_, egress_metadata.payload_length, 16);
    add(ipv6.payloadLen, egress_metadata.payload_length, 16);

}

action mpls_ipv6_udp_ethernet_push3_rewrite() {
    copy_header(inner_ethernet, ethernet);
    push(mpls, 3);
    f_insert_mpls_ipv6_udp();
    add(udp.length_, egress_metadata.payload_length, 34);
    add(ipv6.payloadLen, egress_metadata.payload_length, 34);
}

action mpls_ipv6_udp_ip_push3_rewrite() {
    push(mpls, 3);
    f_insert_mpls_ipv6_udp();
    add(udp.length_, egress_metadata.payload_length, 20);
    add(ipv6.payloadLen, egress_metadata.payload_length, 20);
}
#endif /* IPV6_TUNNEL_DISABLE */

#endif /* MPLS_DISABLE */
#endif /* TUNNEL_DISABLE */

action f_insert_ipv4_header(proto) {
    add_header(ipv4);
    modify_field(ipv4.protocol, proto);
    modify_field(ipv4.ttl, 64);
    modify_field(ipv4.version, 0x4);
    modify_field(ipv4.ihl, 0x5);
    modify_field(ipv4.diffserv, 0);
    modify_field(ipv4.identification, 0);
    modify_field(ipv4.flags, 0x2);
}

action f_insert_ipv6_header(proto) {
    add_header(ipv6);
    modify_field(ipv6.version, 0x6);
    modify_field(ipv6.nextHdr, proto);
    modify_field(ipv6.hopLimit, 64);
    modify_field(ipv6.trafficClass, 0);
    modify_field(ipv6.flowLabel, 0);
}

@pragma ternary 1
table tunnel_encap_process_outer {
    reads {
        tunnel_metadata.egress_tunnel_type : exact;
#ifndef MPLS_DISABLE
        tunnel_metadata.egress_header_count : exact;
#endif /* MPLS_DISABLE */
    }
    actions {
        nop;
#ifdef SRV6_ENABLE
	//        srv6_rewrite;
#endif /* SRV6_ENABLE */
#ifndef TUNNEL_DISABLE
        ipv4_vxlan_rewrite;
#ifndef GENEVE_DISABLE
        ipv4_genv_rewrite;
#endif /* GENEVE_DISABLE */
#ifndef NVGRE_DISABLE
        ipv4_nvgre_rewrite;
#endif /* NVGRE_DISABLE */
        ipv4_gre_rewrite;
        ipv4_ip_rewrite;
#ifndef IPV6_TUNNEL_DISABLE
        ipv6_gre_rewrite;
        ipv6_ip_rewrite;
#ifndef NVGRE_DISABLE
        ipv6_nvgre_rewrite;
#endif /* NVGRE_DISABLE */
        ipv6_vxlan_rewrite;
#ifndef GENEVE_DISABLE
        ipv6_genv_rewrite;
#endif /* GENEVE_DISABLE */
#endif /* IPV6_TUNNEL_DISABLE */
#ifndef MPLS_DISABLE
        mpls_ethernet_push1_rewrite;
        mpls_ip_push1_rewrite;
        mpls_ethernet_push2_rewrite;
        mpls_ip_push2_rewrite;
        mpls_ethernet_push3_rewrite;
        mpls_ip_push3_rewrite;
#ifdef MPLS_UDP_ENABLE
        mpls_ipv4_udp_push_rewrite;
        mpls_ipv4_udp_ethernet_push1_rewrite;
        mpls_ipv4_udp_ip_push1_rewrite;
        mpls_ipv4_udp_ethernet_push2_rewrite;
        mpls_ipv4_udp_ip_push2_rewrite;
        mpls_ipv4_udp_ethernet_push3_rewrite;
        mpls_ipv4_udp_ip_push3_rewrite;
#ifndef INNER_IPV6_DISABLE
        mpls_ipv6_udp_push_rewrite;
        mpls_ipv6_udp_ethernet_push1_rewrite;
        mpls_ipv6_udp_ip_push1_rewrite;
        mpls_ipv6_udp_ethernet_push2_rewrite;
        mpls_ipv6_udp_ip_push2_rewrite;
        mpls_ipv6_udp_ethernet_push3_rewrite;
        mpls_ipv6_udp_ip_push3_rewrite;
#endif /* INNER_IPV6_DISABLE */
#endif /* MPLS_UDP_ENABLE */
#endif /* MPLS_DISABLE */
#endif /* TUNNEL_DISABLE */
    }
    size : TUNNEL_HEADER_TABLE_SIZE;
}


/*****************************************************************************/
/* Tunnel rewrite                                                            */
/*****************************************************************************/
action set_ipv4_tunnel_rewrite_details(ipv4_sa) {
    modify_field(ipv4.srcAddr, ipv4_sa);
}

#ifndef IPV6_TUNNEL_DISABLE
action set_ipv6_tunnel_rewrite_details(ipv6_sa) {
    modify_field(ipv6.srcAddr, ipv6_sa);
}
#endif /* IPV6_TUNNEL_DISABLE */

#ifndef MPLS_DISABLE

action set_mpls_rewrite_push1_core(label1, exp1, ttl1, smac_idx, dmac_idx) {
    modify_field(mpls[0].label, label1);
    modify_field(mpls[0].exp, exp1);
    modify_field(mpls[0].ttl, ttl1);
}

action set_mpls_rewrite_push1(label1, exp1, ttl1, smac_idx, dmac_idx, bos) {
    set_mpls_rewrite_push1_core(label1, exp1, ttl1, smac_idx, dmac_idx);
    modify_field(mpls[0].bos, bos);
}

action set_mpls_rewrite_push2_core(label1, exp1, ttl1, label2, exp2, ttl2,
                              smac_idx, dmac_idx) {
    modify_field(mpls[1].label, label2);
    modify_field(mpls[1].exp, exp2);
    modify_field(mpls[1].ttl, ttl2);
    modify_field(mpls[0].bos, 0x0);
    set_mpls_rewrite_push1_core(label1, exp1, ttl1, smac_idx, dmac_idx);
}

action set_mpls_rewrite_push2(label1, exp1, ttl1, label2, exp2, ttl2,
                              smac_idx, dmac_idx, bos) {
    set_mpls_rewrite_push2_core(label1, exp1, ttl1, label2, exp2, ttl2,smac_idx, dmac_idx);
    modify_field(mpls[1].bos, bos);
}

action set_mpls_rewrite_push3(label1, exp1, ttl1, label2, exp2, ttl2,
                              label3, exp3, ttl3, smac_idx, dmac_idx, bos) {
    modify_field(mpls[2].label, label3);
    modify_field(mpls[2].exp, exp3);
    modify_field(mpls[2].ttl, ttl3);
    modify_field(mpls[2].bos, bos);
    modify_field(mpls[1].bos, 0x0);
    set_mpls_rewrite_push2_core(label1, exp1, ttl1, label2, exp2, ttl2,smac_idx, dmac_idx);
}

#ifdef MPLS_UDP_ENABLE
action set_mpls_udp_rewrite_push0(ipv4_sa) {
    set_ipv4_tunnel_rewrite_details(ipv4_sa);
}

action set_mpls_udp_rewrite_push1_core(label1, exp1, ttl1) {
    modify_field(mpls[0].label, label1);
    modify_field(mpls[0].exp, exp1);
    modify_field(mpls[0].ttl, ttl1);
}

action set_mpls_udp_rewrite_push1(label1, exp1, ttl1, ipv4_sa, bos) {
    set_ipv4_tunnel_rewrite_details(ipv4_sa);
    modify_field(mpls[0].bos, bos);
    set_mpls_udp_rewrite_push1_core(label1, exp1, ttl1);
}

action set_mpls_udp_rewrite_push2_core(label1, exp1, ttl1, label2, exp2, ttl2) {
    modify_field(mpls[1].label, label2);
    modify_field(mpls[1].exp, exp2);
    modify_field(mpls[1].ttl, ttl2);
    set_mpls_udp_rewrite_push1_core(label1, exp1, ttl1);
}

action set_mpls_udp_rewrite_push2(label1, exp1, ttl1, label2, exp2, ttl2,
                              ipv4_sa, bos) {
    set_ipv4_tunnel_rewrite_details(ipv4_sa);
    modify_field(mpls[1].bos, bos);
    set_mpls_udp_rewrite_push2_core(label1, exp1, ttl1, label2, exp2, ttl2);
}

action set_mpls_udp_rewrite_push3_core(label1, exp1, ttl1, label2, exp2, ttl2,
                                       label3, exp3, ttl3) {
    modify_field(mpls[2].label, label3);
    modify_field(mpls[2].exp, exp3);
    modify_field(mpls[2].ttl, ttl3);
    set_mpls_udp_rewrite_push2_core(label1, exp1, ttl1, label2, exp2, ttl2);
}

action set_mpls_udp_rewrite_push3(label1, exp1, ttl1, label2, exp2, ttl2,
                              label3, exp3, ttl3, ipv4_sa, bos) {
   set_ipv4_tunnel_rewrite_details(ipv4_sa);
   modify_field(mpls[2].bos, bos);
   set_mpls_udp_rewrite_push3_core(label1, exp1, ttl1, label2, exp2, ttl2, label3, exp3, ttl3);
}
#endif /* MPLS_UDP_ENABLE */

#endif /* MPLS_DISABLE */

#ifdef SRV6_ENABLE

action set_srv6_tunnel_rewrite_details(mac_sa, mac_da, ipv6_sa) {
    modify_field(ipv6.srcAddr, ipv6_sa);
    modify_field(ethernet.srcAddr, mac_sa);
    modify_field(ethernet.dstAddr, mac_sa);
}

table tunnel_rewrite {
    reads {
        egress_metadata.outer_bd : exact;
    }
    actions {
        nop;
        set_srv6_tunnel_rewrite_details;
    }
    size : TUNNEL_REWRITE_TABLE_SIZE;
}

#else
table tunnel_rewrite {
    reads {
        tunnel_metadata.tunnel_index : exact;
    }
    actions {
        nop;
#if !defined(TUNNEL_DISABLE)
	set_ipv4_tunnel_rewrite_details;
#ifndef IPV6_TUNNEL_DISABLE
	set_ipv6_tunnel_rewrite_details;
#endif /* IPV6_TUNNEL_DISABLE */
#endif /* !TUNNEL_DISABLE */
#ifdef SRV6_ENABLE
        //set_sr_rewrite_segments0;
        set_srv6_rewrite_segments1;
#ifndef SRH_MAX_SEGMENTS_1
        set_srv6_rewrite_segments2;
        set_srv6_rewrite_segments3;
#endif /* SRH_MAX_SEGMENTS_1 */
#endif /* SRV6_ENABLE */
#ifndef MPLS_DISABLE
        set_mpls_rewrite_push1;
        set_mpls_rewrite_push2;
        set_mpls_rewrite_push3;
#ifdef MPLS_UDP_ENABLE
        set_mpls_udp_rewrite_push0;
        set_mpls_udp_rewrite_push1;
        set_mpls_udp_rewrite_push2;
        set_mpls_udp_rewrite_push3;
#endif /* MPLS_UDP_ENABLE */
#endif /* MPLS_DISABLE */
#ifdef FABRIC_ENABLE
        fabric_unicast_rewrite;
#ifndef MULTICAST_DISABLE
        fabric_multicast_rewrite;
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
    }
    size : TUNNEL_REWRITE_TABLE_SIZE;
}
#endif /* SRV6_ENABLE */

#if !defined(TUNNEL_DISABLE)
/*****************************************************************************/
/* Tunnel destination IP rewrite                                             */
/*****************************************************************************/
action rewrite_tunnel_ipv4_dst(ip) {
    modify_field(ipv4.dstAddr, ip);
}

table ipv4_tunnel_dst_rewrite {
    reads {
        tunnel_metadata.tunnel_dst_index : exact;
    }
    actions {
        rewrite_tunnel_ipv4_dst;
    }
    default_action: rewrite_tunnel_ipv4_dst(0);
    size : IPV4_TUNNEL_DST_REWRITE_TABLE_SIZE;
}


#ifndef IPV6_TUNNEL_DISABLE
action rewrite_tunnel_ipv6_dst(ip) {
    modify_field(ipv6.dstAddr, ip);
}

table ipv6_tunnel_dst_rewrite {
    reads {
        tunnel_metadata.tunnel_dst_index : exact;
#ifdef SRV6_ENABLE
        l3_metadata.vrf : exact;
#endif
    }
    actions {
        nop;
#ifndef SRV6_ENABLE
        rewrite_tunnel_ipv4_dst;
#endif
        rewrite_tunnel_ipv6_dst;
    }
#ifdef SRV6_ENABLE
    default_action: rewrite_tunnel_ipv6_dst(0);
#else
    default_action: rewrite_tunnel_ipv4_dst(0);
#endif
    size : IPV6_TUNNEL_DST_REWRITE_TABLE_SIZE;
}
#endif /* IPV6_TUNNEL_DISABLE */

//#ifdef SRV6_ENABLE
///*****************************************************************************/
///* Tunnel MAC rewrite                                                        */
///*****************************************************************************/
//action rewrite_tunnel_mac(smac, dmac) {
//    modify_field(ethernet.srcAddr, smac);
//    modify_field(ethernet.dstAddr, dmac);
//}
//
//table tunnel_mac_rewrite {
//    reads {
//        egress_metadata.outer_bd : exact;
//    }
//    actions {
//        nop;
//        rewrite_tunnel_mac;
//    }
//    size : EGRESS_OUTER_BD_MAPPING_TABLE_SIZE;
//}
//#endif /* !TUNNEL_DISABLE */
//
//
//#else
/*****************************************************************************/
/* Tunnel source MAC rewrite                                                 */
/*****************************************************************************/
action rewrite_tunnel_smac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table tunnel_smac_rewrite {
    reads {
        tunnel_metadata.tunnel_smac_index : exact;
    }
    actions {
        nop;
        rewrite_tunnel_smac;
    }
    size : TUNNEL_SMAC_REWRITE_TABLE_SIZE;
}
#endif /* !TUNNEL_DISABLE */

/*****************************************************************************/
/* Tunnel destination MAC rewrite                                            */
/*****************************************************************************/
action rewrite_tunnel_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table tunnel_dmac_rewrite {
    reads {
        tunnel_metadata.tunnel_dmac_index : exact;
    }
    actions {
        nop;
        rewrite_tunnel_dmac;
    }
    size : TUNNEL_DMAC_REWRITE_TABLE_SIZE;
}

/*****************************************************************************/
/* Tunnel encap processing                                                   */
/*****************************************************************************/
control process_tunnel_encap {
    if (tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE) {
#if !defined(TUNNEL_DISABLE)
        /* derive egress vni if it was not included in rewrite table entry */
        if (tunnel_metadata.vnid == 0) {
          apply(egress_vni);
        }

        /* Move L3/L4 headers to inner */
        apply(tunnel_encap_process_inner);

        /* Add outer L3/L4 headers */
        apply(tunnel_encap_process_outer);

        /* egress outer bd properties */
        process_egress_outer_bd();

        /* derive tunnel properties and rewrite tunnel src ip */
        apply(tunnel_rewrite);

        /* rewrite tunnel dst ip */
#if !defined(IPV6_TUNNEL_DISABLE)
	    if ((tunnel_metadata.egress_tunnel_type == EGRESS_TUNNEL_TYPE_IPV6_VXLAN) or
            (tunnel_metadata.egress_tunnel_type == EGRESS_TUNNEL_TYPE_IPV6_GRE) or
            (tunnel_metadata.egress_tunnel_type == EGRESS_TUNNEL_TYPE_IPV6_IP)) {
	        apply(ipv6_tunnel_dst_rewrite);
	    } else {
	        apply(ipv4_tunnel_dst_rewrite);
	    }
#else
        apply(ipv4_tunnel_dst_rewrite);
#endif /* IPV6_TUNNEL_DISABLE */

        /* rewrite tunnel src mac */
        apply(tunnel_smac_rewrite);
#endif /* !TUNNEL_DISABLE */

#if !defined(TUNNEL_DISABLE) || defined(DTEL_REPORT_ENABLE)
        /* rewrite tunnel dst mac */
        apply(tunnel_dmac_rewrite);
#endif /* !TUNNEL_DISABLE || DTEL_REPORT_ENABLE */
    }
}

/*****************************************************************************/
/* Tunnel ID processing                                                      */
/*****************************************************************************/
#if defined(TUNNEL_NEXTHOP_ENABLE)
action set_tunnel_mgid(mc_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_b, mc_index);
}

table tunnel_to_mgid_mapping {
    reads {
        tunnel_metadata.tunnel_dst_index : exact;
    }

    actions {
        set_tunnel_mgid;
    }
    default_action : set_tunnel_mgid(0);
    size: TUNNEL_TO_MGID_MAPPING_TABLE_SIZE;
}
#endif /* TUNNEL_NEXTHOP_ENABLE */

#ifdef SRV6_ENABLE
field_list tunnel_hash_fields {
    hash_metadata.hash1;
}

field_list_calculation tunnel_hash {
    input {
        tunnel_hash_fields;
    }
    algorithm {
        identity;
        crc_16_dect;
    }
    output_width : 14;
}

action_selector tunnel_ecmp_selector {
    selection_key : tunnel_hash;
    selection_mode : fair;
}

action_profile tunnel_ecmp_action_profile {
    actions {
        nop;
        set_tunnel_ecmp_nexthop_details;
    }
    size : TUNNEL_ECMP_SELECT_TABLE_SIZE;
    dynamic_action_selection : ecmp_selector;
}

action set_tunnel_ecmp_nexthop_details(ifindex, port_lag_index, outer_bd, outer_dmac) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
    modify_field(ingress_metadata.egress_outer_bd, outer_bd);
//    modify_field(ingress_metadata.egress_outer_dmac, outer_dmac);
}

table tunnel_ecmp_group {
    reads {
        tunnel_metadata.tunnel_dst_index : exact;
    }
    action_profile: tunnel_ecmp_action_profile;
    size : TUNNEL_ECMP_GROUP_TABLE_SIZE;
}

#endif
control process_tunnel_id {
#ifdef SRV6_ENABLE
    apply(tunnel_ecmp_group);
#elif defined(TUNNEL_NEXTHOP_ENABLE)
    apply(tunnel_to_mgid_mapping);
#endif /* TUNNEL_NEXTHOP_ENABLE */
}
