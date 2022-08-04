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
#define DROP_UNKNOWN                       0

#define DROP_OUTER_SRC_MAC_ZERO            10
#define DROP_OUTER_SRC_MAC_MULTICAST       11
#define DROP_OUTER_DST_MAC_ZERO            12
#define DROP_OUTER_ETHERNET_MISS           13
#define DROP_SRC_MAC_ZERO                  14
#define DROP_SRC_MAC_MULTICAST             15
#define DROP_DST_MAC_ZERO                  16

#define DROP_OUTER_IP_VERSION_INVALID      25
#define DROP_OUTER_IP_TTL_ZERO             26
#define DROP_OUTER_IP_SRC_MULTICAST        27
#define DROP_OUTER_IP_SRC_LOOPBACK         28
#define DROP_OUTER_IP_MISS                 29
#define DROP_OUTER_IP_IHL_INVALID          30
#define DROP_IP_VERSION_INVALID            40
#define DROP_IP_TTL_ZERO                   41
#define DROP_IP_SRC_MULTICAST              42
#define DROP_IP_SRC_LOOPBACK               43
#define DROP_IP_IHL_INVALID                44

#define DROP_PORT_VLAN_MAPPING_MISS        55
#define DROP_STP_CHECK_FAIL_INGRESS        56
#define DROP_STP_CHECK_FAIL_EGRESS         57
#define DROP_SAME_IFINDEX                  58
#define DROP_MULTICAST_SNOOPING_ENABLED    59

#define DROP_MTU_CHECK_FAIL                70
#define DROP_TRAFFIC_MANAGER               71
#define DROP_METER                         72
#define DROP_WRED                          73

#define DROP_ACL_DENY                      80
#define DROP_RACL_DENY                     81
#define DROP_URPF_CHECK_FAIL               82
#define DROP_IPSG_MISS                     83
#define DROP_IFINDEX                       84
#define DROP_CPU_COLOR_YELLOW              85
#define DROP_CPU_COLOR_RED                 86
#define DROP_STORM_CONTROL_COLOR_YELLOW    87
#define DROP_STORM_CONTROL_COLOR_RED       88

#define DROP_L2_MISS_UNICAST               89
#define DROP_L2_MISS_MULTICAST             90
#define DROP_L2_MISS_BROADCAST             91

#define DROP_EGRESS_ACL_DENY               92
#define DROP_NHOP                          93

#define DROP_RMAC_HIT_NON_IP               94
#define DROP_MLAG                          95

#define DROP_TTL4                          96
#define SAME_PORT_CHECK                    97
#define PFC_TC_DROP                        98

#define DROP_CSUM_ERROR                    100
#define DROP_PARSER_ERROR                  101

#define DROP_OTHERS_INGRESS                254
#define DROP_OTHERS_EGRESS                 255
#define SWITCH_MAX_DROP_REASONS            256
