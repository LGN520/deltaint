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
#ifdef __TARGET_BMV2__
#define BMV2
#endif

#ifdef __TARGET_TOFINO__
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/pktgen_headers.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/wred_blackbox.p4>
#else
#include "includes/tofino.p4"
#endif

#include "includes/p4features.h"
#include "includes/drop_reason_codes.h"
#include "includes/cpu_reason_codes.h"
#include "includes/p4_pktgen.h"
#include "includes/defines.p4"
#include "includes/p4_table_sizes.h"
#include "includes/headers.p4"
#include "includes/parser.p4"

#include "mtel/mtel.p4"

/* METADATA */
header_type ingress_metadata_t {
    fields {
        ingress_port : 9;                         /* input physical port */
        port_lag_index : PORT_LAG_INDEX_BIT_WIDTH;      /* ingress port index */
        egress_port_lag_index : PORT_LAG_INDEX_BIT_WIDTH;/* egress port index */
        ifindex : IFINDEX_BIT_WIDTH;              /* ingress interface index */
        egress_ifindex : IFINDEX_BIT_WIDTH;       /* egress interface index */
        port_type : 2;                         /* ingress port type */

        outer_bd : BD_BIT_WIDTH;               /* outer BD */
        bd : BD_BIT_WIDTH;                     /* BD */

        drop_flag : 1;                         /* if set, drop the packet */
        drop_reason : 8;                       /* drop reason */

        control_frame: 1;                      /* control frame */
        bypass_lookups : 16;                  /* list of lookups to skip */
        egress_outer_bd : BD_BIT_WIDTH;
        egress_outer_dmac : 48;
    }
}

header_type egress_metadata_t {
    fields {
#ifdef PTP_ENABLE
        capture_tstamp_on_tx : 1;              /* request for packet departure time capture */
#endif
        bypass : 1;                            /* bypass egress pipeline */
        port_type : 2;                         /* egress port type */
        payload_length : 16;                   /* payload length for tunnels */
        smac_idx : 9;                          /* index into source mac table */
        bd : BD_BIT_WIDTH;                     /* egress inner bd */
        outer_bd : BD_BIT_WIDTH;               /* egress inner bd */
        mac_da : 48;                           /* final mac da */
        routed : 1;                            /* is this replica routed */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */
        drop_reason : 8;                       /* drop reason */
        ifindex : IFINDEX_BIT_WIDTH;           /* egress interface index */
        egress_port :  9;                      /* original egress port */
    }
}

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 16;                           /* multicast group */
        lf_field_list : 32;                       /* Learn filter field list */
        egress_rid : 16;                          /* replication index */
        ingress_global_timestamp : 32;
    }
}

/* Global config information */
header_type global_config_metadata_t {
    fields {
        enable_dod : 1;                        /* Enable Deflection-on-Drop */
        switch_id  : 32;                       /* Switch Id */
    }
}

#if defined(MSDC_IPV4_PROFILE)
@pragma pa_container_size ingress ig_intr_md_for_tm.mcast_grp_b 16
#endif
#ifdef SFLOW_ENABLE
@pragma pa_atomic ingress ingress_metadata.sflow_take_sample
@pragma pa_solitary ingress ingress_metadata.sflow_take_sample
#endif
@pragma pa_atomic egress egress_metadata.port_type
@pragma pa_solitary egress egress_metadata.port_type
#if defined(GENERIC_INT_LEAF_PROFILE)
@pragma pa_solitary ingress ingress_metadata.drop_reason
@pragma pa_container_size ingress ingress_metadata.drop_reason 8
#endif
#if defined(Q0_PROFILE)
@pragma pa_container_size ingress ingress_metadata.egress_ifindex 32
#endif

// Workaround for COMPILER-788
#if defined(MSDC_PROFILE) || defined(ENT_DC_GENERAL_PROFILE) || \
    defined(M0_PROFILE)
@pragma pa_solitary ingress ingress_metadata.ingress_port
#endif
// Workaround for COMPILER-844
#ifdef INT_EP_ENABLE
@pragma pa_solitary ingress ingress_metadata.ingress_port
#endif

metadata ingress_metadata_t ingress_metadata;

#ifdef DTEL_REPORT_LB_ENABLE
@pragma pa_no_overlay egress egress_metadata.routed
@pragma pa_solitary egress egress_metadata.routed
#endif
// Workaround for COMPILER-844
#ifdef INT_EP_ENABLE
@pragma pa_solitary egress egress_metadata.egress_port
#endif
metadata egress_metadata_t egress_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;
metadata global_config_metadata_t global_config_metadata;

#include "switch_config.p4"
#include "port.p4"
#include "l2.p4"
#include "l3.p4"
#include "ipv4.p4"
#include "ipv6.p4"
#include "tunnel.p4"
#include "acl.p4"
#include "nat.p4"
#include "multicast.p4"
#include "nexthop.p4"
#include "rewrite.p4"
#include "security.p4"
#include "fabric.p4"
#include "egress_filter.p4"
#include "mirror.p4"
#include "hashes.p4"
#include "meter.p4"
#include "sflow.p4"
#include "bfd.p4"
#include "qos.p4"
#include "sr.p4"
#include "flowlet.p4"
#include "pktgen.p4"
#include "failover.p4"
#include "ila.p4"
#include "wred.p4"
#include "dtel.p4"
#include "dtel_int.p4"
#include "dtel_postcard.p4"

action nop() {
}

action on_miss() {
}

control ingress {
//----------------------------------------------------------------------
#if defined(ENT_FIN_POSTCARD_PROFILE)
//----------------------------------------------------------------------

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();

    /* process outer packet headers */
    process_validate_outer_header();

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* spanning tree state checks */
    process_ingress_stp();

    /* ingress fabric processing */
    process_ingress_fabric();

    /* storm control */
    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control();
    }

    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* l2 lookups */
    process_mac();

    /* port and vlan ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
        process_mac_acl();
    } else {
        process_ip_acl();
    }

    process_ingress_port_mirroring();

    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        apply(rmac) {
            rmac_hit {
                if (((ingress_metadata.bypass_lookups & 0x0002) == 0)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                        (ipv4_metadata.ipv4_unicast_enabled == 1)) {
                            process_ipv4_fib();
                    }
                }
            }
        }
    } else {
        process_multicast();
    }

    /* prepare metadata for DTel */
    process_dtel_ingress_prepare();

    /* int_sink process for packets with int_header */
    process_dtel_int_sink();

    /* compute hashes based on packet type  */
    process_hashes_1();
    process_hashes_2();


    /* apply DTel watchlist */
    process_dtel_watchlist();

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

    /* INT i2e mirror */
    process_dtel_int_upstream_report();

    /* update statistics */
    process_ingress_bd_stats();
    process_ingress_acl_stats();
    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control_stats();
    }

    /* decide final forwarding choice */
    process_fwd_results();

    /* ingress qos map */
    process_ingress_qos_map();

    /* IPv4 Mirror ACL */
    if (l3_metadata.lkp_ip_type == 1) {
        process_ipv4_mirror_acl();
    }

    /* meter index */
    process_meter_index();

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* meter action/stats */
    process_meter_action();

    /* set queue id for tm */
    process_traffic_class();


    process_dtel_mod_watchlist();


    if (ingress_metadata.egress_ifindex == 0x3FFF) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
        /* resolve final egress port for unicast traffic */
        process_lag();
    }


    /* generate learn notify digest if permitted */
    process_mac_learning();

    process_ingress_mirror_acl_stats();


    /* apply DTel queue related watchlist after queue is chosen */
    process_dtel_queue_watchlist();


    /* system acls */
    if (ingress_metadata.port_type != 1) {
        process_system_acl();
    }

#if defined(PORT_DROP_STATS_ENABLE)
    process_ingress_port_drop_stats();
#endif /* PORT_DROP_STATS_ENABLE */

    /* PPG Stats */
    process_ingress_ppg_stats();

    /* ECN ACL */
    process_ecn_acl();

    /* Peer-link */
    /* YID rewrite for CPU-TX or peer-link cases */
    if (ingress_metadata.port_type == 2) {
      process_cpu_packet();
    } else {
      process_peer_link_properties();
    }

//----------------------------------------------------------------------
#elif defined(SRV6_L3VPN_PROFILE)
  //----------------------------------------------------------------------
  /* Input Port */
  process_ingress_port_mapping();

  apply(my_sid) {
    nop {
          //        local_sid_miss {
        if(valid(fabric_header_cpu)) {
            apply(cpu_packet_transform);
        } else {
            apply(port_vlan_to_bd_mapping) {
                miss { apply(vlan_to_bd_mapping); }
            }
        }
        apply(adjust_lkp_fields);
    }
    l3vpn_term {
            //        default {
      apply(adjust_lkp_fields_inner);
    }
  }

  /* validate packet */
  process_validate_packet();

  //    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
  apply(mac_acl);
  //    }

  /* Router MAC Check */
  apply(rmac);

  /* perform ingress l4 port range */
  process_ingress_l4port();

  /* spanning tree state checks */
  process_ingress_stp();

  if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
    apply(ip_acl);
  }

  /* ingress fabric processing */
  if (ingress_metadata.port_type != PORT_TYPE_NORMAL) {
    apply(fabric_ingress_dst_lkp);
  }

  /* l2 lookups */
  process_mac();

  /* Hash Calculation - Step 1 */
  process_hashes_1();

  //    apply(rmac) {
  //        rmac_hit {
  // Route Lookups
  if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
    if ((l3_metadata.rmac_hit == 1) or (tunnel_metadata.l3_tunnel_terminate == 1)) {
      if (DO_LOOKUP(L3)) {
	if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
	  process_ipv4_fib();
	} else if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
	  process_ipv6_fib();
	}
      }
    }
  }
  //        }
  //    }

  /* Ingress ACL */
  if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
    apply(ipv6_acl);
  }

  /* decide final forwarding choice */
  //    process_fwd_results();

  /* Hash Calculation - Step 2 */
  process_hashes_2();

  process_ingress_port_mirroring();

  /* ingress qos map */
  process_ingress_qos_map();

  /* update statistics */
  process_ingress_bd_stats();
  process_ingress_acl_stats();

  /* ecmp/nexthop lookup */
  process_nexthop();

  /* set queue id for tm */
  process_traffic_class();

  if (tunnel_metadata.tunnel_dst_index != 0) {
    /* tunnel id */
    process_tunnel_id();
  }

  /* final output resolution */
  if ((l3_metadata.rmac_hit == FALSE) and (ingress_metadata.egress_ifindex == IFINDEX_FLOOD)) {
    /* resolve multicast index for flooding */
    process_multicast_flooding();
  } else {
    /* resolve final egress port for unicast traffic */
    process_lag();
  }

  /* generate learn notify digest if permitted */
  process_mac_learning();

  /* system acls */
  if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
    process_system_acl();
  }

  /* PPG Stats */
  process_ingress_ppg_stats();

//-------------------------------
#elif defined(L3_INT_LEAF_PROFILE)
//-------------------------------

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* process outer packet headers */
    process_validate_outer_header();

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* spanning tree state checks */
    process_ingress_stp();

    /* ingress fabric processing */
    process_ingress_fabric();

    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* l2 lookups */
    process_mac();

    process_ingress_port_mirroring();

    process_tcp_flags();

    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        apply(rmac) {
            rmac_hit {
                if (DO_LOOKUP(L3)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                        (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                            process_ipv4_fib();
                    } else {
                        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                            (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                            process_ipv6_fib();
                        }
                    }
                }
            }
        }
    }

    /* port and vlan ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE or acl_metadata.mac_pkt_classify == TRUE) {
        process_mac_acl();
    } else {
        process_ip_acl();
    }

    /* prepare metadata for DTel */
    process_dtel_ingress_prepare();

    /* int_sink process for packets with int_header */
    process_dtel_int_sink();

    /* compute hashes based on packet type  */
    process_hashes_1();
    process_hashes_2();

    /* apply DTel watchlist */
    process_dtel_watchlist();

    /* INT i2e mirror */
    process_dtel_int_upstream_report();

    /* update statistics */
    process_ingress_bd_stats();
    process_ingress_acl_stats();
    process_storm_control_stats();

    /* decide final forwarding choice */
    process_fwd_results();

    /* ingress qos map */
    process_ingress_qos_map();

    /* IPv4 Mirror ACL */
//    if (l3_metadata.lkp_ip_type == 1) {
//        process_ipv4_mirror_acl();
//    }

    /* meter index */
    process_meter_index();

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* meter action/stats */
    process_meter_action();

    /* set queue id for tm */
    process_traffic_class();

    /* IPv6 Mirror ACL */
    //    if (l3_metadata.lkp_ip_type == 2) {
    //        process_ipv6_mirror_acl();
    //    }

    process_dtel_mod_watchlist();

    if (ingress_metadata.egress_ifindex == 0x3FFF) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
      /* resolve final egress port for unicast traffic */
      process_lag();
    }

    /* generate learn notify digest if permitted */
    process_mac_learning();

    //    process_ingress_mirror_acl_stats();

    /* apply DTel queue related watchlist after queue is chosen */
    process_dtel_queue_watchlist();

    /* system acls */
    if (ingress_metadata.port_type != 1) {
        process_system_acl();
    }

    /* PPG Stats */
    process_ingress_ppg_stats();

    /* Peer-link */
    /* YID rewrite for CPU-TX or peer-link cases */
    if (ingress_metadata.port_type == 2) {
      process_cpu_packet();
    } else {
      process_peer_link_properties();
    }

//----------------------------------------------------------------------
#elif defined(Q0_PROFILE)
//----------------------------------------------------------------------

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();

    /* process outer packet headers */
    process_validate_outer_header();

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* ingress fabric processing */
    process_ingress_fabric();

    process_ingress_port_mirroring();

    /* validate packet */
//    process_validate_packet(); //??????

    /* perform ingress l4 port range */
    process_ingress_l4port();

    process_mac_acl();

    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        apply(rmac) {
            rmac_hit {
                if (DO_LOOKUP(L3)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4_WITH_OPTIONS) or (l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                        (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                            process_ipv4_fib();
                    } else {
                        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                            (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                            process_ipv6_fib();
                        }
                    }
                }
                    }
            default {
                if (DO_LOOKUP(L2)) {
                    apply(dmac);
                }
            }
        }
    } else {
        apply(ipv4_multicast_bridge);
    }

    /* port and vlan ACL */
//    if (DO_LOOKUP(ACL)) {
//        if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
//            process_mac_acl();
//        }
//    }

    process_tcp_flags();

    if(l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
      apply(compress_ipv6_flow_label);
    }

    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control();
    }

    /* compute hashes based on packet type  */
    process_hashes_1();

//    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
//        apply(rmac) {
//            rmac_hit {
//                if (DO_LOOKUP(L3)) {
//                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
//                        (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
//                            process_ipv4_fib();
//                    } else {
//                        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
//                            (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
//                            process_ipv6_fib();
//                        }
//                    }
//                }
//            }
//        }
//    } else {
//        apply(ipv4_multicast_bridge);
//    }

//    if ((l3_metadata.rmac_hit == 1 ) and (l3_metadata.lkp_ip_type == IPTYPE_IPV6) and (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
//         process_ipv6_fib();
//    }
//
    /* port and vlan ACL */
    if (DO_LOOKUP(ACL)) {
        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4_WITH_OPTIONS) or (l3_metadata.lkp_ip_type == IPTYPE_IPV4)) {
            apply(ip_acl);
        } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
            apply(ipv6_acl);
        }
    }
    /* source mac lookup */
    if (DO_LOOKUP(SMAC_CHK) and
        (ingress_metadata.port_type == PORT_TYPE_NORMAL)) {
        apply(smac);
    }

    if(valid(gre) and valid(inner_ipv6)) {
      apply(compute_inner_ipv6_hashes);
    }

    /* decide final forwarding choice */
//    process_fwd_results();

    if(ingress_metadata.port_type == PORT_TYPE_CPU and fabric_header.mcast == 1) {
      apply(fabric_mcast_packet);
    } else {
      /* ingress qos map */
      process_ingress_qos_map();
    }

    /* generate learn notify digest if permitted */
    process_mac_learning();

    if (DO_LOOKUP(ACL)) {
        if ((l2_metadata.lkp_pkt_type == L2_UNICAST and l3_metadata.rmac_hit == 1) \
                or (l2_metadata.lkp_pkt_type == L2_MULTICAST)) {
            if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4_WITH_OPTIONS) or (l3_metadata.lkp_ip_type == IPTYPE_IPV4)) {
                process_ipv4_racl();
            } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
                process_ipv6_racl();
            }
        }
    }

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

    process_hashes_2();

    /* update statistics */
    process_ingress_bd_stats();

    process_ingress_acl_stats();

    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control_stats();
    }

    /* DTEL mirror session selection */
    apply(dtel_mirror_session);

    /* RACL stats */
    process_ingress_racl_stats();

    /* IPv4 Mirror ACL */
//    if (l3_metadata.lkp_ip_type == 1) {
//        process_ipv4_mirror_acl();
//    }

    /* meter index */
    process_meter_index();

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* spanning tree state checks */
    process_ingress_stp();

    /* meter action/stats */
    process_meter_action();

    if (DO_LOOKUP(TC)) {
      /* set queue id for tm */
      process_traffic_class();
    }

    /* IPv6 Mirror ACL */
    //    if (l3_metadata.lkp_ip_type == 2) {
    //        process_ipv6_mirror_acl();
    //    }

    if (ingress_metadata.egress_ifindex == 0x3FFF) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
      /* resolve final egress port for unicast traffic */
      process_lag();
    }

    //    process_ingress_mirror_acl_stats();

    /* DTEL Watchlist */
    process_dtel_watchlist();

    process_dtel_mod_watchlist();

    /* system acls */
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl();
    }
    /* PPG Stats */
    process_ingress_ppg_stats();

    /* apply DTel queue related watchlist after queue is chosen */
    process_dtel_queue_watchlist();

    /* Peer-link */
    /* YID rewrite for CPU-TX or peer-link cases */
    if (ingress_metadata.port_type == PORT_TYPE_CPU) {
      process_cpu_packet();
    } else {
      process_peer_link_properties();
    }

//----------------------------------------------------------------------
#elif defined(M0_PROFILE)
//----------------------------------------------------------------------

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* read and apply system configuration parameters */
    process_global_params();

    /* process outer packet headers */
    process_validate_outer_header();

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* spanning tree state checks */
    process_ingress_stp();

    /* ingress fabric processing */
    process_ingress_fabric();

    /* storm control */
    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control();
    }

    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* l2 dmac lookup */
    if (DO_LOOKUP(L2)) {
        apply(dmac);
    }

    /* compute hashes based on packet type  */
    process_hashes_1();

    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        apply(rmac) {
            rmac_hit {
                if (DO_LOOKUP(L3)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                        (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                            process_ipv4_urpf();
                            process_ipv4_fib();

                    } else {
                        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                            (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                            process_ipv6_urpf();
                            process_ipv6_fib();
                        }
                    }
                    process_urpf_bd();
                }
            }
        }
    }

    /* port and vlan ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
        process_mac_acl();
    } else {
        process_ip_acl();
    }

    /* source mac lookup */
    if (DO_LOOKUP(SMAC_CHK) and
        (ingress_metadata.port_type == PORT_TYPE_NORMAL)) {
        apply(smac);
    }

    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control_stats();
    }

    process_ingress_port_mirroring();

    process_hashes_2();

    /* apply DTel watchlist */
    process_dtel_watchlist();

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

    /* update statistics */
    process_ingress_bd_stats();
    process_ingress_acl_stats();

    /* decide final forwarding choice */
    process_fwd_results();

    /* ingress qos map */
    process_ingress_qos_map();

    /* IPv4 Mirror ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
        process_ipv4_mirror_acl();
    }

    /* meter index */
    process_meter_index();

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* meter action/stats */
    process_meter_action();

    /* set queue id for tm */
    process_traffic_class();

    /* IPv6 Mirror ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
        process_ipv6_mirror_acl();
    }

    if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
        /* resolve final egress port for unicast traffic */
        process_lag();
    }

    /* generate learn notify digest if permitted */
    process_mac_learning();

    /* IPv6 Mirror ACL */
    process_ingress_mirror_acl_stats();

    /* system acls */
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl();
    }

    /* PPG Stats */
    process_ingress_ppg_stats();

    /* apply DTel queue related watchlist after queue is chosen */
    process_dtel_queue_watchlist();

    /* ECN ACL */
    process_ecn_acl();

//----------------------------------------------------------------------
#elif defined(MSDC_IPV4_PROFILE)
//----------------------------------------------------------------------
    /* Input Port */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();

    /* process outer packet headers */
    apply(validate_outer_ethernet) {
        malformed_outer_ethernet_packet {
        }
        default {
            if (valid(ipv4)) {
                validate_outer_ipv4_header();
            } else if (valid(ipv6)) {
      	        validate_outer_ipv6_header();
            }
        }
    }

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* ingress fabric processing */
    if (ingress_metadata.port_type != PORT_TYPE_NORMAL) {
        apply(fabric_ingress_dst_lkp);
    }

    /* tunnel termination processing */
    process_tunnel_term();
    if (tunnel_metadata.tunnel_terminate==TRUE) {
        apply(ingress_vni);
    }

    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* l2 lookups */
    if (DO_LOOKUP(L2)) {
        apply(dmac);
    }

    /* Router MAC Check */
    apply(rmac);

    /* Ingress MAC ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
        apply(mac_acl);
    }

    // Route Lookups
    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        if ((l3_metadata.rmac_hit == 1) or (tunnel_metadata.l3_tunnel_terminate == 1)) {
                if (DO_LOOKUP(L3)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                        process_ipv4_fib();
                    } else if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                        process_ipv6_fib();
                    }
                }
        }
    }

    /* Hash Calculation - Step 1 */
    process_hashes_1();

    /* Ingress IP ACL */
    if (DO_LOOKUP(ACL)) {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
            apply(ip_acl);
        } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
            apply(ipv6_acl);
        }
    }

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

    /* Hash Calculation - Step 2 */
    process_hashes_2();

    /* Source MAC lookup */
    if (DO_LOOKUP(SMAC_CHK) and
        (ingress_metadata.port_type == PORT_TYPE_NORMAL)) {
        apply(smac);
    }

    /* ingress qos map */
    process_ingress_qos_map();

    /* update ingress acl statistics */
    process_ingress_acl_stats();

    /* Mirror ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
        process_ipv6_mirror_acl();
    } else {
        process_ipv4_mirror_acl();
    }

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* set queue id for tm */
    process_traffic_class();

    /* final output resolution */
    if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
        if (tunnel_metadata.tunnel_dst_index != 0) {
            /* tunnel id */
            process_tunnel_id();
        } else {
            /* resolve final egress port for unicast traffic */
            process_lag();
        }
    }

    /* generate learn notify digest if permitted */
    process_mac_learning();

    /* Mirror ACL Stats */
    process_ingress_mirror_acl_stats();

    /* ingress bd stats */
    process_ingress_bd_stats();

    /* system acls */
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl();
    }

    /* PPG Stats */
    process_ingress_ppg_stats();

    /* ECN ACL */
    process_ecn_acl();

//----------------------------------------------------------------------
#elif defined(MSDC_L3_PROFILE)
//----------------------------------------------------------------------
    /* Input Port */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();

    /* process outer packet headers */
    apply(validate_outer_ethernet) {
        malformed_outer_ethernet_packet {
        }
        default {
            if (valid(ipv4)) {
                validate_outer_ipv4_header();
            } else if (valid(ipv6)) {
      	        validate_outer_ipv6_header();
            }
        }
    }
#ifdef MTEL_ENABLE
    apply(mtel_epoch);
    if (mtel_least_int.valid == 1 and
        mtel_least_int.start_index == mtel_least_int.next_index){
        apply(mtel_least_int_finish);
    }
#endif // MTEL_ENABLE

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* ingress fabric processing */
    if (ingress_metadata.port_type == PORT_TYPE_CPU){
        apply(fabric_ingress_dst_lkp);
    }

#ifdef MTEL_ENABLE
    apply(mtel_epoch_mask);
    apply(mtel_hash_prepare);
#endif // MTEL_ENABLE

    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* l2 lookups */
    process_mac();

    /* Router MAC Check */
    apply(rmac);

    /* Ingress ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
        apply(mac_acl);
    } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
        apply(ip_acl);
    }

#ifdef MTEL_ENABLE
    if (mtel_least_int.valid == 1){
      apply(mtel_epoch_load);
    }else {
      apply(mtel_epoch_save);
    }
#endif // MTEL_ENABLE

    /* Hash Calculation - Step 1 */
    process_hashes_1();

#ifdef MTEL_ENABLE
    if (mtel_md.monitor == 1){
        apply(mtel_cms_update_hashtable_1);
    }
    if (mtel_md.monitor == 1 and ipv4.valid==1){
        apply(mtel_cms_update_hashtable_2);
    }else if (mtel_md.monitor == 1 and ipv6.valid==1){
        apply(mtel_cms_v6_update_hashtable_2);
    }
#endif // MTEL_ENABLE

    // Route Lookups
    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        if ((l3_metadata.rmac_hit == 1) or (tunnel_metadata.l3_tunnel_terminate == 1)) {
            if (DO_LOOKUP(L3)) {
                if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                    process_ipv4_fib();
                } else if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                    process_ipv6_fib();
                }
            }
        }
    }

    /* Ingress ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
        apply(ipv6_acl);
    }

#ifdef MTEL_ENABLE
    if (mtel_md.monitor == 1){
        apply(mtel_cms_update_hashtable_4);
    }
    if (mtel_md.monitor == 1 and ipv4.valid==1){
        apply(mtel_cms_update_hashtable_3);
    }else if (mtel_md.monitor == 1 and ipv6.valid==1){
        apply(mtel_cms_v6_update_hashtable_3);
    }
#endif // MTEL_ENABLE

    /* decide final forwarding choice */
    process_fwd_results();

    /* Hash Calculation - Step 2 */
    process_hashes_2();

    /* ingress qos map */
    process_ingress_qos_map();

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

    /* ecmp/nexthop lookup */
    process_nexthop();

#ifdef MTEL_ENABLE
    apply(mtel_cms_subtract);
#endif // MTEL_ENABLE

    /* set queue id for tm */
    process_traffic_class();

    /* ingress port mirror */
    process_ingress_port_mirroring();

#ifdef MTEL_ENABLE
    apply(mtel_cms_find_min);
#endif // MTEL_ENABLE

    /* final output resolution */
    if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
        /* resolve final egress port for unicast traffic */
        process_lag();
    }

#ifdef MTEL_ENABLE
    apply(mtel_pktsize_index);
    apply(mtel_fsd_reg1_index);

    if (mtel_md.monitor == 1){
        // don't change reg2 index for recirc packet
        apply(mtel_fsd_reg2_index);
        apply(mtel_port_summary_map);
    }
#endif // MTEL_ENABLE

    /* generate learn notify digest if permitted */
    process_mac_learning();

    /* system acls */
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl();
    }

    /* PPG Stats */
    process_ingress_ppg_stats();

    /* ECN ACL */
    process_ecn_acl();

    /* update statistics */
    process_ingress_bd_stats();
    process_ingress_acl_stats();

#ifdef MTEL_ENABLE
    if (mtel_least_int.valid == 1 or ethernet.etherType==ETHERTYPE_BF_PKTGEN){
        apply(mtel_late_routing);
    }
    if (mtel_md.monitor == 1){
        apply(mtel_pktsize_update);
        if (fsd_md.reg1_bin_index != fsd_md.reg2_bin_index){
            apply(mtel_fsd_reg1_update);
        }
    }
    if (mtel_least_int.valid == 1 or
        fsd_md.reg2_bin_index != fsd_md.reg1_bin_index and mtel_md.monitor==1){
        apply(mtel_fsd_reg2_update);
    }
#endif // MTEL_ENABLE

//----------------------------------------------------------------------
#elif defined(ENT_DC_GENERAL_PROFILE)
//----------------------------------------------------------------------

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();

    /* process outer packet headers */
    process_validate_outer_header();

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* spanning tree state checks */
    process_ingress_stp();

    /* ingress fabric processing */
    process_ingress_fabric();

    /* tunnel termination processing */
    process_tunnel_term();
    if (tunnel_metadata.tunnel_terminate==TRUE) {
        apply(ingress_vni);
    }

    /* storm control */
    process_storm_control();

    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* MAC ACL */
    if (DO_LOOKUP(ACL)) {
        apply(mac_acl);
    }

    /* l2 lookups */
    process_mac();

    // Route Lookups
    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
        apply(rmac) {
            rmac_hit {
                if (DO_LOOKUP(L3)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                        process_ipv4_fib();
                    } else if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                        process_ipv6_fib();
                    }
                }
            }
        }
    } else {
        process_multicast();
    }

    /* IPV4 ACL */
    if (DO_LOOKUP(ACL)) {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
            apply(ip_acl);
        } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
            apply(ipv6_acl);
        }
    }

    /* compute hashes based on packet type  */
    process_hashes_1();
    process_hashes_2();

    /* update statistics */
    process_ingress_bd_stats();
    process_ingress_acl_stats();

    /* decide final forwarding choice */
    process_fwd_results();

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

    /* ingress qos map */
    process_ingress_qos_map();

    /* storm control stats */
    process_storm_control_stats();

    /* ecmp/nexthop lookup */
    process_nexthop();

    /* set queue id for tm */
    process_traffic_class();

    process_ingress_port_mirroring();

    if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
        if (tunnel_metadata.tunnel_dst_index != 0) {
            /* tunnel id */
            process_tunnel_id();
        } else {
            /* resolve final egress port for unicast traffic */
            process_lag();
        }
    }

    /* generate learn notify digest if permitted */
    process_mac_learning();

    /* PPG Stats */
    process_ingress_ppg_stats();

    /* system acls */
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl();
    }

//----------------------------------------------------------------------
#else /* !ENT_DC_GENERAL_PROFILE */
//----------------------------------------------------------------------

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();
#ifdef PKTGEN_ENABLE
    if (VALID_PKTGEN_PACKET) {
        /* process pkt_gen generated packets */
        process_pktgen();
    } else {
#endif /* PKTGEN_ENABLE */
    /* process outer packet headers */
    process_validate_outer_header();

    /* process bfd rx packets */
    process_bfd_rx_packet();

    /* derive bd and its properties  */
    process_port_vlan_mapping();

    /* spanning tree state checks */
    process_ingress_stp();

    /* ingress fabric processing */
    process_ingress_fabric();

#if !defined(TUNNEL_PARSING_DISABLE)
    /* tunnel termination processing */
    process_tunnel();
#endif /* !TUNNEL_PARSING_DISABLE */

    /* IPSG */
    process_ip_sourceguard();

    /* ingress sflow determination */
    process_ingress_sflow();

#if !defined(GENERIC_INT_LEAF_PROFILE)
    /* storm control */
    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control();
    }
#endif


#ifdef PKTGEN_ENABLE
    }
#endif
    /* common (tx and rx) bfd processing */
    process_bfd_packet();

#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(GENERIC_INT_LEAF_PROFILE)
    process_dtel_ingress_prepare();
#endif

#ifdef FABRIC_ENABLE
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
#endif
#ifndef MPLS_DISABLE
    if (not (valid(mpls[0]) and (l3_metadata.fib_hit == TRUE))) {
#endif /* MPLS_DISABLE */
    /* validate packet */
    process_validate_packet();

    /* perform ingress l4 port range */
    process_ingress_l4port();

    /* l2 lookups */
    process_mac();

#if defined(GENERIC_INT_SPINE_PROFILE)
    process_dtel_ingress_prepare();
#endif

#if !defined(ACL_SWAP)
    /* port and vlan ACL */
#ifdef MAC_PKT_CLASSIFY_ENABLE
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE or acl_metadata.mac_pkt_classify == TRUE) {
#else
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
#endif
        process_mac_acl();
    } else {
        process_ip_acl();
    }
#endif

#if defined(INGRESS_PORT_MIRROR_ENABLE)
    process_ingress_port_mirroring();
#endif /* INGRESS_PORT_MIRROR_ENABLE */

#if defined(ACL_SWAP) && \
    (defined(L3_HEAVY_INT_SPINE_PROFILE) || defined(L3_HEAVY_INT_LEAF_PROFILE) || \
     defined(GENERIC_INT_LEAF_PROFILE) || defined(GENERIC_INT_SPINE_PROFILE))
#ifdef MAC_PKT_CLASSIFY_ENABLE
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE or acl_metadata.mac_pkt_classify == TRUE) {
#else
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
#endif
        process_mac_acl();
    }
#endif /* ACL_SWAP */

#ifdef TCP_FLAGS_LOU_ENABLE
    process_tcp_flags();
#endif

    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
#if defined(L2_DISABLE) && defined(L2_MULTICAST_DISABLE) && defined(L3_MULTICAST_DISABLE)
        {
            {
#else
        apply(rmac) {
            rmac_hit {
#endif /* L2_DISABLE && L2_MULTICAST_DISABLE && L3_MULTICAST_DISABLE */
                if (DO_LOOKUP(L3)) {
                    if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                        (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                            process_ipv4_urpf();
                            process_ipv4_fib();

#ifdef IPV6_DISABLE
		    }
#else
                    } else {
                        if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                            (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                            process_ipv6_urpf();
                            process_ipv6_fib();
                        }
                    }
#endif /* IPV6_DISABLE */
                    process_urpf_bd();
                }
            }
        }
    } else {
        process_multicast();
    }

#if defined(GENERIC_INT_LEAF_PROFILE)
    process_dtel_make_upstream_digest();
    process_dtel_int_set_sink();
#endif

#ifdef L3_HEAVY_INT_LEAF_PROFILE
    process_dtel_mod_watchlist();
    process_dtel_int_sink();
#endif

    /* router ACL/PBR */
    if (DO_LOOKUP(ACL)) {
        if ((l2_metadata.lkp_pkt_type == L2_UNICAST and l3_metadata.rmac_hit == 1) \
                or (l2_metadata.lkp_pkt_type == L2_MULTICAST)) {
            if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
                process_ipv4_racl();
            } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
                process_ipv6_racl();
            }
        }
    }


#if defined(ACL_SWAP)
    /* port and vlan ACL */
#ifdef MAC_PKT_CLASSIFY_ENABLE
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE or acl_metadata.mac_pkt_classify == TRUE) {
#else
    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
#endif
#if !defined(L3_HEAVY_INT_LEAF_PROFILE) && !defined(L3_HEAVY_INT_SPINE_PROFILE) && \
    !defined(GENERIC_INT_LEAF_PROFILE) && !defined(GENERIC_INT_SPINE_PROFILE)
        process_mac_acl();
#endif
    } else {
        process_ip_acl();
    }
#endif

    /* ingress NAT */
    process_ingress_nat();

#ifdef ENT_DC_AGGR_PROFILE
    /* FCoE ACL */
    apply(fcoe_acl);
#endif /* ENT_DC_AGGR_PROFILE */

#ifndef MPLS_DISABLE
    }
#endif /* MPLS_DISABLE */
#ifdef FABRIC_ENABLE
    }
#endif

#if !defined(GENERIC_INT_LEAF_PROFILE) && !defined(L3_HEAVY_INT_LEAF_PROFILE) \
    && !defined(GENERIC_INT_SPINE_PROFILE)
    /* prepare metadata for DTel */
    process_dtel_ingress_prepare();
#endif

#ifndef L3_HEAVY_INT_LEAF_PROFILE
    /* int_sink process for packets with int_header */
    process_dtel_int_sink();
#endif

#ifdef L3_HEAVY_INT_LEAF_PROFILE
    process_hashes_1();

    process_dtel_int_watchlist();
#endif

    /* compute hashes based on packet type  */
#ifndef L3_HEAVY_INT_LEAF_PROFILE
    process_hashes_1();
#endif
    process_hashes_2();

    /* apply DTel watchlist */
    process_dtel_watchlist();

#if defined(GENERIC_INT_LEAF_PROFILE) || defined(GENERIC_INT_SPINE_PROFILE)
    /* ingress qos map */
    process_ingress_qos_map();
#endif


#if defined(L3_HEAVY_INT_LEAF_PROFILE) || defined(L3_HEAVY_INT_SPINE_PROFILE) \
    || defined(TRANSIENT_LOOP_PREVENTION)
    /* decide final forwarding choice */
    process_fwd_results();
#endif

    /* Ingress vlan membership check */
    process_ingress_vlan_mbr();

#ifndef TRANSIENT_LOOP_PREVENTION
    /* INT i2e mirror */
    process_dtel_int_upstream_report();
#endif

#ifdef FABRIC_ENABLE
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
#endif /* FABRIC_ENABLE */

    /* update statistics */
    process_ingress_bd_stats();
    process_ingress_acl_stats();
#if !defined(GENERIC_INT_LEAF_PROFILE) && !defined(GENERIC_INT_SPINE_PROFILE)
    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      process_storm_control_stats();
    }
#endif

#if !defined(L3_HEAVY_INT_LEAF_PROFILE) && !defined(L3_HEAVY_INT_SPINE_PROFILE) \
    && !defined(TRANSIENT_LOOP_PREVENTION)
    /* decide final forwarding choice */
    process_fwd_results();
#endif

#if !defined(GENERIC_INT_LEAF_PROFILE) && !defined(GENERIC_INT_SPINE_PROFILE)
    /* ingress qos map */
    process_ingress_qos_map();
#endif

#if !defined(GENERIC_INT_LEAF_PROFILE) && !defined(L3_HEAVY_INT_LEAF_PROFILE) \
    && !defined(GENERIC_INT_SPINE_PROFILE) && !defined(L3_HEAVY_INT_SPINE_PROFILE) \
    && !defined(TRANSIENT_LOOP_PREVENTION)
    /* IPv4 Mirror ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
        process_ipv4_mirror_acl();
    }
#endif

    /* flowlet */
    process_flowlet();

    /* meter index */
    process_meter_index();

#if defined(GENERIC_INT_LEAF_PROFILE)
    if(l3_metadata.rmac_hit == 0 and multicast_metadata.mcast_route_hit == 0 and multicast_metadata.mcast_bridge_hit == 0) {
      /* storm control */
      process_storm_control();
      /* storm control stats */
      process_storm_control_stats();
    }
#endif

    /* ecmp/nexthop lookup */
    process_nexthop();

#if defined(GENERIC_INT_LEAF_PROFILE) || defined(L3_HEAVY_INT_LEAF_PROFILE) \
    || defined(GENERIC_INT_SPINE_PROFILE) || defined(L3_HEAVY_INT_SPINE_PROFILE)
    /* IPv4 Mirror ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
        process_ipv4_mirror_acl();
    }
#endif

#ifdef TRANSIENT_LOOP_PREVENTION
    /* IPv4 Mirror ACL */
#if !defined(IPV4_DISABLE) && defined(INGRESS_MIRROR_ACL_ENABLE)
    apply(ipv4_mirror_acl) {
        miss {
            /* INT i2e mirror */
            process_dtel_int_upstream_report();
        }
    }
#else
    /* INT i2e mirror */
    process_dtel_int_upstream_report();
#endif
#endif /* TRANSIENT_LOOP_PREVENTION */

    /* meter action/stats */
    process_meter_action();

    /* set queue id for tm */
    process_traffic_class();

    /* IPv6 Mirror ACL */
    if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
        process_ipv6_mirror_acl();
    }

#ifndef L3_HEAVY_INT_LEAF_PROFILE
    process_dtel_mod_watchlist();
#endif

#ifdef TRANSIENT_LOOP_PREVENTION
    apply(nexthop_details) {
        nop {
            if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
                /* resolve multicast index for flooding */
                process_multicast_flooding();
            }
        }
    }

    if(ingress_metadata.port_lag_index != 0) {
       /* resolve final egress port for unicast traffic */
       process_lag();
    }
#else
    if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
        /* resolve multicast index for flooding */
        process_multicast_flooding();
    } else {
        if (tunnel_metadata.tunnel_dst_index != 0) {
            process_tunnel_id();
        } else {
            /* resolve final egress port for unicast traffic */
            process_lag();
        }
    }
#endif

    /* generate learn notify digest if permitted */
    process_mac_learning();
#ifdef FABRIC_ENABLE
    }
#endif /* FABRIC_ENABLE */

    /* IPv6 Mirror ACL */
    process_ingress_mirror_acl_stats();

    /* resolve fabric port to destination device */
    process_fabric_lag();

    /* apply DTel queue related watchlist after queue is chosen */
    process_dtel_queue_watchlist();

    /* RACL stats */
    process_ingress_racl_stats();

#if !defined(DTEL_DROP_REPORT_ENABLE) && !defined(DTEL_QUEUE_REPORT_ENABLE)
    /* PPG Stats */
    process_ingress_ppg_stats();
#endif /* DTEL_DROP_REPORT_ENABLE && DTEL_QUEUE_REPORT_ENABLE */

    /* system acls */
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        process_system_acl();
    }

#if defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)
    /* PPG Stats */
    process_ingress_ppg_stats();
#endif /* DTEL_DROP_REPORT_ENABLE && DTEL_QUEUE_REPORT_ENABLE */

    /* ECN ACL */
    process_ecn_acl();

    /* Peer-link */
    /* YID rewrite for CPU-TX or peer-link cases */
    if (ingress_metadata.port_type == PORT_TYPE_CPU) {
      process_cpu_packet();
    } else {
      process_peer_link_properties();
    }

//----------------------------------------------------------------------
#endif /* !ENT_DC_GENERAL_PROFILE */
//----------------------------------------------------------------------
}

control egress {

//----------------------------------------------------------------------
#ifdef SRV6_L3VPN_PROFILE
//----------------------------------------------------------------------
  if (egress_metadata.bypass == FALSE) {

    /* set info from rid */
    if(eg_intr_md.egress_rid != 0) {
      //            apply(rid);
//      apply(mcast_egress_ifindex);
    }

    apply(egress_port_mapping) {
      egress_port_type_normal {

	//                /* check if pkt is mirrored */
	//                if (pkt_is_mirrored) {
	//                    process_mirroring();
	//                } else {
	/* apply nexthop_index based packet rewrites */
	process_rewrite();

	/* strip vlan header */
	process_vlan_decap();

	/* perform tunnel decap */
	process_tunnel_decap();
	//                }
      }
    }

    /* egress bd properties */
    process_egress_bd();

    /* wred processing */
    process_wred();

    /* rewrite source/destination mac if needed */
    process_mac_rewrite();

    /* egress qos map */
    process_egress_qos_map();

    /* update egress bd stats */
    process_egress_bd_stats();

    /* egress outer bd properties */
    process_egress_outer_bd();

    /* perform tunnel encap */
    if (tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE) {

      /* Move L3/L4 headers to inner */
      apply(tunnel_encap_process_inner);

      /* Add outer L3/L4 headers */
      apply(tunnel_encap_process_outer);

      /* derive tunnel properties and rewrite tunnel src_ip, src_mac and dst_mac  */
      apply(tunnel_rewrite);

      /* rewrite tunnel dst ip */
      apply(ipv6_tunnel_dst_rewrite);
    }

    /* egress mtu checks */
    process_mtu();

    if (pkt_is_mirrored) {
      process_mirroring();
    }

    /* Egress Port Mirroring */
    if (not pkt_is_mirrored) {
      process_egress_port_mirroring();
    }

    /* egress vlan translation */
    if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
      /* egress vlan translation */
      process_vlan_xlate();
    }

    /* WRED stats */
    process_wred_stats();

    /* apply egress acl */
    apply(egress_system_acl);
  }

  /* Queue Stats */
  process_egress_queue_stats();

  /* Capture timestamp */
  apply(capture_tstamp);  // TODO}

//-------------------------------
#elif defined(L3_INT_LEAF_PROFILE)
//-------------------------------

    /* Egress Port Mirroring */
    if (not pkt_is_mirrored) {
        process_egress_port_mirroring();
    }

    /* Record egress port for telemetry in case of DoD */
    if (not pkt_is_mirrored) {
        process_dtel_record_egress_port();
    }

    /* check for -ve mirrored pkt */
    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* multi-destination replication */
            process_rid();

            /* check if pkt is mirrored */
            if (not pkt_is_mirrored) {
                process_dtel_prepare_egress();
            }

            /* multi-destination replication */
            process_replication();

            if (not pkt_is_mirrored) {
                /* DTel processing -- detect local change and e2e */
                process_dtel_local_report1();
            }

            /* determine egress port properties */
            apply(egress_port_mapping) {
                egress_port_type_normal {

                    if (pkt_is_not_mirrored) {
                        /* strip vlan header */
                        process_vlan_decap();
                    }

                    process_egress_qos_map();
                }
            }

            if (not pkt_is_mirrored) {
                process_dtel_queue_alert_update();
            }

            if(egress_metadata.port_type == PORT_TYPE_NORMAL) {
	        if (pkt_is_not_mirrored) {
                    process_rewrite();
                }
            }

            if (not pkt_is_mirrored) {
                /* DTel processing -- detect local change and e2e */
                process_dtel_local_report2();
            } else {
                process_mirroring();
            }

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {

                /* perform egress l4 port range */
                process_egress_l4port();

                /* egress bd properties */
                process_egress_bd();

                if (not pkt_is_mirrored) {
                    /* wred processing */
                    process_wred();
                }

                /* rewrite source/destination mac if needed */
                process_mac_rewrite();

                /* update egress bd stats */
                process_egress_bd_stats();

                /* update egress acl stats */
                process_egress_acl_stats();
            }
        } else {
            process_dtel_deflect_on_drop();
        }

        if (pkt_is_mirrored) {
            /* DTel processing -- convert h/w port to frontend port */
            process_dtel_port_convert();
            process_dtel_report_encap();
        } else {
            /* DTel processing -- insert header */
            process_dtel_insert();
        }

        if (eg_intr_md.deflection_flag == FALSE) {
	    /* rewrite tunnel dst mac */
	    apply(tunnel_dmac_rewrite);

            /* egress mtu checks */
            process_mtu();

            /* update L4 checksums (if needed) */
            process_l4_checksum();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* egress vlan translation */
                process_vlan_xlate();
            }
        }
    }

    /* WRED stats */
    process_wred_stats();

    /* Queue Stats */
    process_egress_queue_stats();

    /* DTel processing -- set or clear INT over L4 DSCP bit */
    process_dtel_int_over_l4_set_dscp();

    /* Capture timestamp */
    apply(capture_tstamp);

    /* apply egress acl */
    process_egress_system_acl();

//-------------------------------
#elif defined(Q0_PROFILE)
//-------------------------------

    if(ingress_metadata.port_type != PORT_TYPE_RECIRC and eg_intr_md.deflection_flag == FALSE) {
      /* determine egress port properties */
      apply(egress_port_mapping);
    }

    /* Egress Port Mirroring */
    if (pkt_is_not_mirrored) {
        process_egress_port_mirroring();
    }

    if (egress_metadata.bypass == FALSE and
        eg_intr_md.deflection_flag == FALSE) {
        /* multi-destination replication */
        process_rid();
    }

    /* Record egress port for telemetry in case of DoD */
    if (pkt_is_not_mirrored) {
        process_dtel_record_egress_port();
    }


    if (ingress_metadata.port_type != PORT_TYPE_RECIRC and egress_metadata.bypass == FALSE and
        eg_intr_md.deflection_flag == FALSE and pkt_is_not_mirrored) {
        /* DTel queue report part 1 */
        process_dtel_prepare_egress();
    }

    /* Queue Stats */
    process_egress_queue_stats();

    /* check for -ve mirrored pkt */
    if (ingress_metadata.port_type != PORT_TYPE_RECIRC and egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* check if pkt is mirrored */
            if (pkt_is_not_mirrored) {
                /* DTel queue report part 2 */
                process_dtel_local_report1();

                process_dtel_queue_alert_update();
            } else {
                /* mirror processing */
                process_mirroring();

                process_dtel_drop_suppress_prepare();

                /* DTel processing -- convert h/w port to frontend port */
                process_dtel_port_convert();
            }

            /* multi-destination replication */
            process_replication();

            /* DTel processing -- detect local change */
            process_dtel_local_report2();

            if(egress_metadata.port_type == PORT_TYPE_NORMAL) {
                process_egress_qos_map();

                if (pkt_is_not_mirrored) {
                    process_rewrite();
                }

                /* perform egress l4 port range */
                process_egress_l4port();
            }

            if (pkt_is_mirrored) {
                process_dtel_report_encap();
            } else {
                /* DTel processing -- e2e */
                process_dtel_local_report3();
            }

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {

                /* egress bd properties */
                process_egress_bd();

                if (pkt_is_not_mirrored) {
                    /* wred processing */
                    apply(wred_index);
                }

                /* egress acl */
                if (valid(ipv6)) {
                    apply(egress_ipv6_acl);
                } else if (valid(ipv4)) {
                    apply(egress_ip_acl);
                } else {
                    apply(egress_mac_acl);
                }

                if (pkt_is_not_mirrored) {
                    apply(wred_action);

                    /* strip vlan header */
                    process_vlan_decap();
                }

                /* rewrite source/destination mac if needed */
                process_mac_rewrite();


                /* update egress bd stats */
                process_egress_bd_stats();

                /* update egress acl stats */
                process_egress_acl_stats();

                process_egress_meter_index();

                /* rewrite tunnel dst mac */
                apply(tunnel_dmac_rewrite);

                /* egress mtu checks */
                process_mtu();

                /* update L4 checksums (if needed) */
                process_l4_checksum();

                process_egress_stp();

                process_egress_meter_action();

                /* WRED stats */
                process_wred_stats();

                /* egress vlan translation */
                process_vlan_xlate();
            }

            /* update DTEL report sequence number */
            process_dtel_report_header_update();
        } else {
            process_dtel_deflect_on_drop();
        }
    }

    if(ingress_metadata.port_type != PORT_TYPE_RECIRC) {
      /* apply egress acl */
      process_egress_system_acl();
    }

//----------------------------------------------------------------------
#elif defined(M0_PROFILE)
//----------------------------------------------------------------------
    /* Record egress port for telemetry in case of DoD */
    if (not pkt_is_mirrored) {
        process_dtel_record_egress_port();
    }

    /* determine egress port properties */
    apply(egress_port_mapping);

    /* check for -ve mirrored pkt */
    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* multi-destination replication */
            process_rid();

            /* check if pkt is mirrored */
            if (not pkt_is_mirrored) {
                /* DTel queue report part 1 */
                process_dtel_prepare_egress();
            } else {
                /* mirror processing */
                process_mirroring();

                process_dtel_drop_suppress_prepare();
            }

            /* multi-destination replication */
            process_replication();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                if (pkt_is_not_mirrored) {
                    /* apply nexthop_index based packet rewrites */
                    process_rewrite();
                }

                if (pkt_is_not_mirrored) {
                    /* strip vlan header */
                    process_vlan_decap();
                }

                /* perform egress l4 port range */
                process_egress_l4port();

                /* egress qos map */
                process_egress_qos_map();

                /* egress bd properties */
                process_egress_bd();

                /* egress mac acl */
                if (not valid(ipv4) and not valid(ipv6)) {
                    apply(egress_mac_acl);
                }
            }

            if (not pkt_is_mirrored) {
                /* DTel queue report part 2 */
                process_dtel_local_report1();
            }

            if (not pkt_is_mirrored) {
                process_dtel_queue_alert_update();
            }

            /* DTel processing -- detect local change */
            process_dtel_local_report2();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {

                /* egress IPv4 acl */
                if (valid(ipv4)) {
                    apply(egress_ip_acl);
                }

                if (not pkt_is_mirrored) {
                    /* wred processing */
                    process_wred();
                }
            }

            if (pkt_is_mirrored) {
                /* DTel processing -- convert h/w port to frontend port */
                process_dtel_port_convert();
                process_dtel_report_encap();
            } else {
                /* DTel processing -- e2e */
                process_dtel_local_report3();
            }

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {

                /* egress IPv6 acl */
                if (valid(ipv6)) {
                    apply(egress_ipv6_acl);
                }

                /* rewrite source/destination mac if needed */
                process_mac_rewrite();

                /* update egress bd stats */
                process_egress_bd_stats();
            }

            apply(tunnel_dmac_rewrite);

            /* egress mtu checks */
            process_mtu();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* update egress acl stats */
                process_egress_acl_stats();

                /* egress vlan translation */
                process_vlan_xlate();

                /* egress stp check */
                process_egress_stp();
            }

            /* update DTEL report sequence number */
            process_dtel_report_header_update();
        } else {
            process_dtel_deflect_on_drop();
        }
    }

    /* pfc acl */
    process_egress_pfc_acl();

    /* WRED stats */
    process_wred_stats();

    /* Queue Stats */
    process_egress_queue_stats();

    /* apply egress acl */
    process_egress_system_acl();
//----------------------------------------------------------------------
#elif defined(MSDC_IPV4_PROFILE)
//----------------------------------------------------------------------
    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* set info from rid */
            if(eg_intr_md.egress_rid != 0) {
                apply(rid);
            }

            apply(egress_port_mapping) {
    	        egress_port_type_normal {

                    /* check if pkt is mirrored */
                    if (pkt_is_mirrored) {
    	                process_mirroring();
                    } else {
        	            /* apply nexthop_index based packet rewrites */
        	            process_rewrite();

         	            /* strip vlan header */
        	            process_vlan_decap();

        	            /* perform tunnel decap */
        	            process_tunnel_decap();

                        /* Mirror ACL */
                        if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
                            process_egress_ipv6_mirror_acl();
                        } else {
                            process_egress_ipv4_mirror_acl();
                        }

    	                /* egress bd properties */
    	                process_egress_bd();

    	                /* wred processing */
    	                process_wred();

    	                /* rewrite source/destination mac if needed */
    	                process_mac_rewrite();

                        /* update egress bd stats */
                        process_egress_bd_stats();

                        /* perform tunnel encap */
                        process_tunnel_encap();

                        /* Mirror ACL Stats */
                        process_egress_mirror_acl_stats();

                        /* egress mtu checks */
                        process_mtu();

                        /* pfc acl */
                        process_egress_pfc_acl();

                        /* egress vlan translation */
                        if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                            /* egress vlan translation */
                            process_vlan_xlate();
                        }

                        /* WRED stats */
                        process_wred_stats();

                        /* apply egress acl */
                        apply(egress_system_acl);
                    }
                }
            }
        }
    }

    /* Queue Stats */
    process_egress_queue_stats();

//----------------------------------------------------------------------
#elif defined(MSDC_L3_PROFILE)
//----------------------------------------------------------------------

    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            if (not pkt_is_mirrored) {
                process_egress_port_mirroring();
            }

            /* set info from rid */
            if(eg_intr_md.egress_rid != 0) {
                apply(rid);
            }

            apply(egress_port_mapping) {
    	        egress_port_type_normal {

                    /* check if pkt is mirrored */
                    if (pkt_is_mirrored) {
    	                process_mirroring();
                    } else {
        	            /* apply nexthop_index based packet rewrites */
        	            process_rewrite();

         	            /* strip vlan header */
        	            process_vlan_decap();
                    }
                }
            }

    	    /* egress bd properties */
    	    process_egress_bd();

    	    /* wred processing */
    	    process_wred();

    	    /* rewrite source/destination mac if needed */
    	    process_mac_rewrite();

    	    /* update egress bd stats */
    	    process_egress_bd_stats();

            /* egress mtu checks */
            process_mtu();

            /* egress vlan translation */
            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* egress vlan translation */
                process_vlan_xlate();
            }

            /* WRED stats */
            process_wred_stats();

            /* apply egress acl */
            apply(egress_system_acl);
         }
     }

    /* Queue Stats */
    process_egress_queue_stats();

#ifdef MTEL_ENABLE
    if (ethernet.etherType == ETHERTYPE_BF_PKTGEN){
        apply(mtel_least_int_start);
    }else{
      if (mtel_least_int.valid == 1 or
         eg_intr_md.deflection_flag == 1 and mtel_md.monitor == 1){
        apply(mtel_drop_reg_update);
      }
      if (mtel_least_int.valid == 1 and mtel_md.set_index == 0){
        apply(mtel_least_int_add);
        apply(mtel_least_int_sub);
      }
    }
#endif // MTEL_ENABLE

//----------------------------------------------------------------------
#elif defined(ENT_DC_GENERAL_PROFILE)
//----------------------------------------------------------------------

    /* check for -ve mirrored pkt */
    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* multi-destination replication */
            process_rid();

            /* multi-destination replication */
            process_replication();

            /* determine egress port properties */
            apply(egress_port_mapping) {
                egress_port_type_normal {

                    if (pkt_is_not_mirrored) {
                        /* apply nexthop_index based packet rewrites */
                        process_rewrite();

                        /* strip vlan header */
                        process_vlan_decap();

                        /* perform tunnel decap */
                        process_tunnel_decap();

                        /* egress qos map */
                        process_egress_qos_map();
                    } else {
                        process_mirroring();
                    }

                }
            }
        }
    }

    /* egress bd properties */
    process_egress_bd();

    //                /* perform egress l4 port range */
    //                process_egress_l4port();
    //
    /* egress acl */
    process_egress_acl();

    /* rewrite source/destination mac if needed */
    process_mac_rewrite();

    /* update egress acl stats */
    process_egress_acl_stats();

    /* perform tunnel encap */
    process_tunnel_encap();

    /* update egress bd stats */
    process_egress_bd_stats();

    /* egress mtu checks */
    process_mtu();

    /* update L4 checksums (if needed) */
    process_l4_checksum();

    if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
        /* egress vlan translation */
        process_vlan_xlate();
        process_egress_stp();
    }

    /* Queue Stats */
    process_egress_queue_stats();

//----------------------------------------------------------------------
#elif defined(ENT_FIN_POSTCARD_PROFILE)
//----------------------------------------------------------------------

    /* Record egress port for telemetry in case of DoD */
    if (not pkt_is_mirrored) {
        process_dtel_record_egress_port();
    }

    /* check for -ve mirrored pkt */
    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* multi-destination replication */
            process_rid();

            /* check if pkt is mirrored */
            if (not pkt_is_mirrored) {
                process_dtel_prepare_egress();
            }

            /* multi-destination replication */
            process_replication();

            if (not pkt_is_mirrored) {
                /* DTel processing -- detect local change and e2e */
                process_dtel_local_report1();
            } else {
                process_dtel_drop_suppress_prepare();
            }

            /* determine egress port properties */
            apply(egress_port_mapping) {
                egress_port_type_normal {

                    if (pkt_is_not_mirrored) {
                    /* apply nexthop_index based packet rewrites */
                        process_rewrite();
                        /* strip vlan header */
                        process_vlan_decap();
                    }

                    /* egress qos map */
                    process_egress_qos_map();
                }
            }

            if (not pkt_is_mirrored) {
                process_dtel_queue_alert_update();
            }

            /* DTel processing -- detect local change */
            process_dtel_local_report2();

            if (pkt_is_mirrored) {
                process_mirroring();
            }

            /* DTel processing -- e2e */
            process_dtel_local_report3();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* perform egress l4 port range */
                process_egress_l4port();

                /* egress bd properties */
                process_egress_bd();

                /* rewrite source/destination mac if needed */
                process_mac_rewrite();

                /* update egress bd stats */
                process_egress_bd_stats();

                /* egress stp check */
                process_egress_stp();
            }

            if (pkt_is_mirrored) {
                /* DTel processing -- convert h/w port to frontend port */
                process_dtel_port_convert();
                process_dtel_report_encap();
            } else {
                /* DTel processing -- insert header */
                process_dtel_insert();
            }

            if (tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE) {
                apply(tunnel_dmac_rewrite);
            }

            /* egress mtu checks */
            process_mtu();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* egress vlan translation */
                process_vlan_xlate();
            }
        } else {
            process_dtel_deflect_on_drop();
        }
    }

    /* Queue Stats */
    process_egress_queue_stats();

    /* apply egress acl */
    process_egress_system_acl();

#if defined(EGRESS_PORT_DROP_STATS_ENABLE)
    process_egress_port_drop_stats();
#endif /* EGRESS_PORT_DROP_STATS_ENABLE */

//----------------------------------------------------------------------
#else
//----------------------------------------------------------------------
    /*
     * if bfd rx pkt is for recirc to correct pipe,
     * skip the rest of the pipeline
     */
    process_bfd_recirc();

    /* Process lag selection fallback */
    process_lag_fallback();

    /* Egress Port Mirroring */
#if defined(EGRESS_PORT_MIRROR_ENABLE)
    if (not pkt_is_mirrored) {
        process_egress_port_mirroring();
    }
#endif /* EGRESS_PORT_MIRROR_ENABLE */

    /* Record egress port for telemetry in case of DoD */
    if (not pkt_is_mirrored) {
        process_dtel_record_egress_port();
    }

    /* check for -ve mirrored pkt */
    if (egress_metadata.bypass == FALSE) {
        if (eg_intr_md.deflection_flag == FALSE) {

            /* multi-destination replication */
            process_rid();

            /* check if pkt is mirrored */
            if (not pkt_is_mirrored) {
                process_egress_bfd_packet();
                process_dtel_prepare_egress();
            } else {
                /* mirror processing */
#ifndef MIRROR_SWAP
                process_mirroring();
#endif
                process_bfd_mirror_to_cpu();
            }

            /* multi-destination replication */
            process_replication();

            if (not pkt_is_mirrored) {
                /* DTel processing -- detect local change and e2e */
                process_dtel_local_report1();
            } else {
                process_dtel_drop_suppress_prepare();
            }

#ifdef L3_HEAVY_INT_LEAF_PROFILE
            apply(egress_port_mapping);
            if (not pkt_is_mirrored) {
                process_dtel_int_edge_ports();
            }
            if(egress_metadata.port_type == PORT_TYPE_NORMAL) { {
#else
            /* determine egress port properties */
            apply(egress_port_mapping) {
                egress_port_type_normal {
#endif /* L3_HEAVY_INT_LEAF_PROFILE */

#ifdef REWRITE_SWAP
#ifdef DTEL_REPORT_ENABLE
                    if (pkt_is_not_mirrored) {
                        process_rewrite();
                    }
#else  /* !DTEL_REPORT_ENABLE */
                    /* apply nexthop_index based packet rewrites */
                    process_rewrite();
#endif /* DTEL_REPORT_ENABLE */
#endif /* REWRITE_SWAP */

                    if (pkt_is_not_mirrored) {
                        /* strip vlan header */
                        process_vlan_decap();
                    }

#if !defined(TUNNEL_PARSING_DISABLE)
                    /* perform tunnel decap */
                    process_tunnel_decap();
#endif /* !TUNNEL_PARSING_DISABLE */

#if !defined(GENERIC_INT_SPINE_PROFILE)
                    /* egress qos map */
                    process_egress_qos_map();
#endif /* GENERIC_INT_SPINE_PROFILE) */

#ifdef DTEL_QUEUE_REPORT_ENABLE
                }
            }
            if (not pkt_is_mirrored) {
                process_dtel_queue_alert_update();
            }
            if(egress_metadata.port_type == PORT_TYPE_NORMAL) { {
#endif /* DTEL_QUEUE_REPORT_ENABLE */

#ifndef REWRITE_SWAP
#ifdef DTEL_REPORT_ENABLE
                    if (pkt_is_not_mirrored) {
                        process_rewrite();
                    }
#else  /* !DTEL_REPORT_ENABLE */
                    /* apply nexthop_index based packet rewrites */
                    process_rewrite();
#endif /* DTEL_REPORT_ENABLE */
#endif /* !REWRITE_SWAP */
                }
            }

#if defined(MIRROR_SWAP) && defined(MSDC_LEAF_DTEL_INT_PROFILE)
            if (pkt_is_mirrored) {
                process_mirroring();
            }
#endif

            /* DTel processing -- detect local change */
            process_dtel_local_report2();

#if defined(MIRROR_SWAP) && !defined(MSDC_LEAF_DTEL_INT_PROFILE)
            if (pkt_is_mirrored) {
                process_mirroring();
            }
#endif

            /* DTel processing -- e2e */
            process_dtel_local_report3();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {

                /* perform egress l4 port range */
                process_egress_l4port();

                /* egress bd properties */
                process_egress_bd();

#if defined(MSDC_LEAF_DTEL_INT_PROFILE)
                /* update egress bd stats */
                process_egress_bd_stats();
#endif /* MSDC_LEAF_DTEL_INT_PROFILE */

                /* egress acl */
                process_egress_acl();

                if (not pkt_is_mirrored) {
                    /* wred processing */
                    process_wred();
                }

                /* rewrite source/destination mac if needed */
                process_mac_rewrite();

#if defined(GENERIC_INT_SPINE_PROFILE)
                /* egress qos map */
                process_egress_qos_map();
#endif /* GENERIC_INT_SPINE_PROFILE */

                /* egress nat processing */
                process_egress_nat();

#if !defined(MSDC_LEAF_DTEL_INT_PROFILE)
                /* update egress bd stats */
                process_egress_bd_stats();
#endif /* !MSDC_LEAF_DTEL_INT_PROFILE */

                /* update egress acl stats */
                process_egress_acl_stats();
            }

#ifdef INT_EP_ENABLE
        } else {
            process_dtel_deflect_on_drop();
        }
#endif

            if (pkt_is_mirrored) {
                /* DTel processing -- convert h/w port to frontend port */
                process_dtel_port_convert();
                process_dtel_report_encap();
            } else {
                /* DTel processing -- insert header */
                process_dtel_insert();
            }

#ifdef INT_L45_DSCP_ENABLE
            /* DTel processing -- set or clear INT over L4 DSCP bit */
            process_dtel_int_over_l4_set_dscp();
#endif

#ifdef INT_EP_ENABLE
        if (eg_intr_md.deflection_flag == FALSE) {
#endif

#if !defined(TUNNEL_PARSING_DISABLE)
            /* perform tunnel encap */
            process_tunnel_encap();
#elif defined(DTEL_REPORT_ENABLE)
	    /* rewrite tunnel dst mac */
	    apply(tunnel_dmac_rewrite);
#endif /* !TUNNEL_PARSING_DISABLE */

#ifdef DC_BASIC_PROFILE
            /* egress stp check */
            process_egress_stp();
#endif /* DC_BASIC_PROFILE */

            /* egress mtu checks */
            process_mtu();

            /* update L4 checksums (if needed) */
            process_l4_checksum();

            if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* egress vlan translation */
                process_vlan_xlate();
#ifndef DC_BASIC_PROFILE
                /* egress stp check */
                process_egress_stp();
#endif /* DC_BASIC_PROFILE */
            }

            /* egress filter */
            process_egress_filter();
#ifndef INT_EP_ENABLE
        } else {
            process_dtel_deflect_on_drop();
#endif /* !INT_EP_ENABLE */
        }
    }

    /* WRED stats */
    process_wred_stats();

    /* Queue Stats */
    process_egress_queue_stats();

    /* Capture timestamp */
#ifdef PTP_ENABLE
    apply(capture_tstamp);
#endif /* PTP_ENABLE */

    /* apply egress acl */
    process_egress_system_acl();
//----------------------------------------------------------------------
#endif
//----------------------------------------------------------------------
}
