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
/* Boolean */
#define FALSE                                  0
#define TRUE                                   1

/* Packet types */
#define L2_UNICAST                             1
#define L2_MULTICAST                           2
#define L2_BROADCAST                           4

#define METER_COLOR_GREEN                      0
#define METER_COLOR_YELLOW                     1
#define METER_COLOR_RED                        2

/* IP types */
#define IPTYPE_NONE                            0
#define IPTYPE_IPV4                            1
#define IPTYPE_IPV6                            2
#define IPTYPE_IPV4_WITH_OPTIONS               5
#define IPTYPE_IPV6_WITH_OPTIONS               6

/* Multicast modes */
#define MCAST_MODE_NONE                        0
#define MCAST_MODE_SM                          1
#define MCAST_MODE_BIDIR                       2

#define MCAST_KEY_TYPE_BD                      0
#define MCAST_KEY_TYPE_VRF                     1

/* URPF modes */
#define URPF_MODE_NONE                         0
#define URPF_MODE_LOOSE                        1
#define URPF_MODE_STRICT                       2

/* NAT modes */
#define NAT_MODE_NONE                          0
#define NAT_MODE_INSIDE                        1
#define NAT_MODE_OUTSIDE                       2

/* ARP opcodes */
#define ARP_OPCODE_NONE                        0
#define ARP_OPCODE_REQ                         1
#define ARP_OPCODE_RES                         2

/* Egress tunnel types */
#define EGRESS_TUNNEL_TYPE_NONE                0
#define EGRESS_TUNNEL_TYPE_IPV4_VXLAN          1
#define EGRESS_TUNNEL_TYPE_IPV6_VXLAN          2
#define EGRESS_TUNNEL_TYPE_IPV4_GENEVE         3
#define EGRESS_TUNNEL_TYPE_IPV6_GENEVE         4
#define EGRESS_TUNNEL_TYPE_IPV4_NVGRE          5
#define EGRESS_TUNNEL_TYPE_IPV6_NVGRE          6
#define EGRESS_TUNNEL_TYPE_IPV4_ERSPAN_T3      7
#define EGRESS_TUNNEL_TYPE_IPV6_ERSPAN_T3      8
#define EGRESS_TUNNEL_TYPE_IPV4_GRE            9
#define EGRESS_TUNNEL_TYPE_IPV6_GRE            10
#define EGRESS_TUNNEL_TYPE_IPV4_IP             11
#define EGRESS_TUNNEL_TYPE_IPV6_IP             12
#define EGRESS_TUNNEL_TYPE_MPLS_L2VPN          13
#define EGRESS_TUNNEL_TYPE_MPLS_L3VPN          14
#define EGRESS_TUNNEL_TYPE_FABRIC              15
#define EGRESS_TUNNEL_TYPE_CPU                 16
#define EGRESS_TUNNEL_TYPE_VXLAN_GPE           17
#define EGRESS_TUNNEL_TYPE_IPV4_DTEL           18
#define EGRESS_TUNNEL_TYPE_IPV6_DTEL           19
#define EGRESS_TUNNEL_TYPE_IPV4_MPLS_UDP_L2VPN 20
#define EGRESS_TUNNEL_TYPE_IPV4_MPLS_UDP_L3VPN 21
#define EGRESS_TUNNEL_TYPE_IPV6_MPLS_UDP_L2VPN 22
#define EGRESS_TUNNEL_TYPE_IPV6_MPLS_UDP_L3VPN 23
#define EGRESS_TUNNEL_TYPE_SRV6                24
#define EGRESS_TUNNEL_TYPE_SRV6_L2VPN          25
#define EGRESS_TUNNEL_TYPE_SRV6_L3VPN          26

#define VRF_BIT_WIDTH                          14
#define BD_BIT_WIDTH                           14

#ifdef NEXTHOP_SCALING
#define NEXTHOP_BIT_WIDTH                      17
#else
#define NEXTHOP_BIT_WIDTH                      16
#endif

#ifdef TUNNEL_SCALING
#define TUNNEL_DST_BIT_WIDTH                      17
#else
#define TUNNEL_DST_BIT_WIDTH                      16
#endif

#ifdef PORT_LABEL_32_BIT
#define PORT_LABEL_WIDTH                       32
#else
#define PORT_LABEL_WIDTH                       16
#endif

#define ECMP_BIT_WIDTH                         10
#define LAG_BIT_WIDTH                          8
#define PORT_LAG_INDEX_BIT_WIDTH               10
#define IFINDEX_BIT_WIDTH                      14

#ifdef RMAC_GROUP_OPTIMIZATION_ENABLE
#define RMAC_GROUP_BIT_WIDTH                    8
#else
#define RMAC_GROUP_BIT_WIDTH                   10
#endif

#ifdef TUNNEL_DMAC_OPTIMIZATION_ENABLE
#define TUNNEL_DMAC_BIT_WIDTH 8
#else
#define TUNNEL_DMAC_BIT_WIDTH 12
#endif

#define STP_GROUP_NONE                         0

#define CPU_MIRROR_SESSION_ID                  250

/* Learning Receivers */
#ifndef __TARGET_TOFINO__
#define MAC_LEARN_RECEIVER                     1024
#else
#define MAC_LEARN_RECEIVER                     0
#endif

/* Nexthop Type */
#define NEXTHOP_TYPE_SIMPLE                    0
#define NEXTHOP_TYPE_ECMP                      1

#define INVALID_PORT_ID                        511

/* ifindex to indicate flood */
#define IFINDEX_FLOOD                          0x3FFF

/* fabric device to indicate mutlicast */
#define FABRIC_DEVICE_MULTICAST                127

/* port type */
#define PORT_TYPE_NORMAL                       0
#define PORT_TYPE_FABRIC                       1
#define PORT_TYPE_CPU                          2
#define PORT_TYPE_RECIRC                       3

#define DEFAULT_INGRESS_COS                    0

/* BYPASS LOOKUP */
#define BYPASS_L2                              0x0001
#define BYPASS_L3                              0x0002
#define BYPASS_ACL                             0x0004
#define BYPASS_QOS                             0x0008
#define BYPASS_METER                           0x0010
#define BYPASS_SYSTEM_ACL                      0x0020
#define BYPASS_PKT_VALIDATION                  0x0040
#define BYPASS_SMAC_CHK                        0x0080
#define BYPASS_NATIVE_VLAN_TAGGING             0x0100
#define BYPASS_TC                              0x4000
#define CPU_TX_FLOOD_TO_VLAN                   0x8000
#define BYPASS_ALL                             0x3FFF

#define DO_LOOKUP(l) \
    ((ingress_metadata.bypass_lookups & BYPASS_##l) == 0)

#define BYPASS_ALL_LOOKUPS \
    (ingress_metadata.bypass_lookups == BYPASS_ALL)

/* Tunnel Termination Type */
#define TUNNEL_TERM_TYPE_P2P  0
#define TUNNEL_TERM_TYPE_MP2P 1

/* ALL_RID */
#define ALL_RID_DEFAULT 0xFFFF

#define VALID_PKTGEN_PACKET \
    (valid(pktgen_port_down) or valid(pktgen_recirc) or valid(pktgen_generic))

/* 3-bit DROP_CTL field */
#define DROP_CTL_FORWARD_BIT 0 // For unicast, multicast and resubmit
#define DROP_CTL_COPY_TO_CPU_BIT 1
#define DROP_CTL_MIRROR_BIT 2
