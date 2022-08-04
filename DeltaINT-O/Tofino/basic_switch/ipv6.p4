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
 * IPv6 processing
 */

/*
 * IPv6 Metadata
 */
header_type ipv6_metadata_t {
    fields {
        lkp_ipv6_sa : 128;                     /* ipv6 source address */
        lkp_ipv6_da : 128;                     /* ipv6 destination address*/
        lkp_srh_da  : 128;

        ipv6_unicast_enabled : 1;              /* is ipv6 unicast routing enabled on BD */
        ipv6_src_is_link_local : 1;            /* source is link local address */
#if !defined(URPF_DISABLE)
        ipv6_urpf_mode : 2;                    /* 0: none, 1: strict, 3: loose */
#endif /* URPF_DISABLE */
        flow_label : 20;                       /* Flow Label from ipv6 header */
    }
}

#if !defined(IPV4_DISABLE) && !defined(IPV6_DISABLE)
@pragma pa_mutually_exclusive ingress ipv4_metadata.lkp_ipv4_sa ipv6_metadata.lkp_ipv6_sa
@pragma pa_mutually_exclusive ingress ipv4_metadata.lkp_ipv4_da ipv6_metadata.lkp_ipv6_da

#ifdef Q0_PROFILE
@pragma pa_mutually_exclusive ingress inner_ipv4.srcAddr inner_ipv6.srcAddr
@pragma pa_mutually_exclusive ingress inner_ipv4.dstAddr inner_ipv6.dstAddr
@pragma pa_mutually_exclusive ingress inner_ipv4.protocol inner_ipv6.nextHdr

@pragma pa_container_size ingress ipv4_metadata.lkp_ipv4_sa 32
@pragma pa_container_size ingress ipv4_metadata.lkp_ipv4_da 32
@pragma pa_container_size ingress ipv6_metadata.lkp_ipv6_sa 32
@pragma pa_container_size ingress ipv6_metadata.lkp_ipv6_da 32

@pragma pa_container_size ingress inner_ipv4.srcAddr 32
@pragma pa_container_size ingress inner_ipv4.dstAddr 32
@pragma pa_container_size ingress inner_ipv6.srcAddr 32
@pragma pa_container_size ingress inner_ipv6.dstAddr 32
#endif

#endif /* !IPV4_DISABLE && !IPV6_DISABLE */

#if defined(TUNNEL_PARSING_DISABLE)
@pragma pa_alias ingress ipv6_metadata.lkp_ipv6_sa ipv6.srcAddr
@pragma pa_alias ingress ipv6_metadata.lkp_ipv6_da ipv6.dstAddr
#endif /* !TUNNEL_PARSING_DISABLE */

#ifdef MSDC_IPV4_PROFILE
  @pragma pa_container_size ingress ipv6_metadata.lkp_ipv6_sa 32
  @pragma pa_container_size ingress ipv6_metadata.lkp_ipv6_da 32
#endif
metadata ipv6_metadata_t ipv6_metadata;

#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE)
/*****************************************************************************/
/* Validate outer IPv6 header                                                */
/*****************************************************************************/
action set_valid_outer_ipv6_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l3_metadata.lkp_dscp, ipv6.trafficClass);
    modify_field(l3_metadata.lkp_ip_version, ipv6.version);
#if defined(TUNNEL_PARSING_DISABLE)
    modify_field(l3_metadata.lkp_ip_proto,   ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl,     ipv6.hopLimit);
#endif /* TUNNEL_PARSING_DISABLE */
}

action set_valid_outer_ipv6_llmc_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l3_metadata.lkp_dscp, ipv6.trafficClass);
    modify_field(l3_metadata.lkp_ip_version, ipv6.version);
#if defined(TUNNEL_PARSING_DISABLE)
    modify_field(l3_metadata.lkp_ip_proto,   ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl,     ipv6.hopLimit);
#endif /* TUNNEL_PARSING_DISABLE */
    modify_field(l3_metadata.lkp_ip_llmc, TRUE);
}

action set_valid_outer_ipv6_mc_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV6);
    modify_field(l3_metadata.lkp_dscp, ipv6.trafficClass);
    modify_field(l3_metadata.lkp_ip_version, ipv6.version);
#if defined(TUNNEL_PARSING_DISABLE)
    modify_field(l3_metadata.lkp_ip_proto,   ipv6.nextHdr);
    modify_field(l3_metadata.lkp_ip_ttl,     ipv6.hopLimit);
#endif /* TUNNEL_PARSING_DISABLE */
    modify_field(l3_metadata.lkp_ip_mc, TRUE);
}

action set_malformed_outer_ipv6_packet(drop_reason) {
#ifdef ALT_INGRESS_DROP_ENABLE
#else
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, drop_reason);
#endif /* ALT_INGRESS_DROP_ENABLE */
}

/*
 * Table: Validate ipv6 packet
 * Lookup: Ingress
 * Validate and extract ipv6 header
 */
table validate_outer_ipv6_packet {
    reads {
        ipv6.version : ternary;
        ipv6.hopLimit : ternary;
        ipv6.srcAddr mask 0xFFFF0000000000000000000000000000 : ternary;
#if !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE)
        ipv6.dstAddr mask 0xFFFF0000000000000000000000000000 : ternary;
#endif /* !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE) */
    }
    actions {
        set_valid_outer_ipv6_packet;
#if !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE)
        set_valid_outer_ipv6_llmc_packet;
        set_valid_outer_ipv6_mc_packet;
#endif /* !defined(L2_MULTICAST_DISABLE) || !defined(L3_MULTICAST_DISABLE) */
        set_malformed_outer_ipv6_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}
#endif /* L3_DISABLE && IPV6_DISABLE */

control validate_outer_ipv6_header {
#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE)
    apply(validate_outer_ipv6_packet);
#endif /* L3_DISABLE && IPV6_DISABLE */
}

#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE)
/*****************************************************************************/
/* IPv6 FIB lookup                                                           */
/*****************************************************************************/
/*
 * Actions are defined in l3.p4 since they are
 * common for both ipv4 and ipv6
 */

#ifdef FIB_ATCAM
action set_ipv6_fib_partition_index(partition_index) {
    modify_field(l3_metadata.fib_partition_index, partition_index);
}

table ipv6_fib_partition {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da mask 0xFFFFFFFFFFFFFFFF0000000000000000 : lpm;
    }
    actions {
        set_ipv6_fib_partition_index;
    }
    size : IPV6_FIB_PARTITION_TABLE_SIZE;
}
#endif /* FIB_ATCAM */

/*
 * Table: Ipv6 LPM Lookup
 * Lookup: Ingress
 * Ipv6 route lookup for longest prefix match entries
 */
#ifdef MSDC_L3_PROFILE
@pragma alpm 1
@pragma ways 5
#else
#if defined(FIB_ALPM)
@pragma alpm 1
@pragma ways 6
#elif defined(FIB_ATCAM)
@pragma atcam_number_partitions IPV6_FIB_PARTITION_TABLE_SIZE
@pragma atcam_partition_index l3_metadata.fib_partition_index
@pragma ways 5
#endif
#endif
table ipv6_fib_lpm {
    reads {
#ifdef FIB_ATCAM
        l3_metadata.fib_partition_index : exact;
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da mask 0xFFFFFFFFFFFFFFFF0000000000000000 : lpm;
#else /* FIB_ATCAM */
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da : lpm;
#endif /* FIB_ATCAM */
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV6_LPM_TABLE_SIZE;
}


/*
 * Table: Ipv6 Host Lookup
 * Lookup: Ingress
 * Ipv6 route lookup for /128 entries
 */
#ifdef IPV6_HOST_TABLE_SIZE
table ipv6_fib {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da : exact;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_myip;
        fib_hit_ecmp;
#ifdef ILA_ENABLE
        ila_hit_nexthop;
        ila_hit_ecmp;
#endif /* ILA_ENABLE */
    }
    size : IPV6_HOST_TABLE_SIZE;
}
#endif /* IPV6_HOST_TABLE_SIZE */

/*
 * Lookup: Ingress
 * Ipv6 route lookup for /64 entries
 */
#ifdef IPV6_HOST64_TABLE_SIZE
table ipv6_fib64 {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_da mask 0xFFFFFFFFFFFFFFFF0000000000000000: exact;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_myip;
        fib_hit_ecmp;
#ifdef ILA_ENABLE
        ila_hit_nexthop;
        ila_hit_ecmp;
#endif /* ILA_ENABLE */
    }
    size : IPV6_HOST64_TABLE_SIZE;
}
#endif /* IPV6_HOST_TABLE_SIZE */
#endif /* L3_DISABLE && IPV6_DISABLE */

control process_ipv6_fib {
#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE)
#if defined(FIB_ATCAM)
    apply(ipv6_fib_partition);
#endif /* FIB_ATCAM */
#ifdef IPV6_HOST_TABLE_SIZE
    apply(ipv6_fib) {
#ifdef IPV6_HOST64_TABLE_SIZE
        on_miss {
            apply(ipv6_fib64) {
#endif /* IPV6_HOST_TABLE_SIZE */
                on_miss {
                    apply(ipv6_fib_lpm);
                }
#ifdef IPV6_HOST64_TABLE_SIZE
            }
        }
#endif /* IPV6_HOST_TABLE_SIZE */
    }
#else
            apply(ipv6_fib_lpm);
#endif /* IPV6_HOST_TABLE_SIZE */
#endif /* L3_DISABLE && IPV6_DISABLE */
}

#if !defined(IPV6_DISABLE) && !defined(URPF_DISABLE)
/*****************************************************************************/
/* IPv6 uRPF lookup                                                          */
/*****************************************************************************/
action ipv6_urpf_hit(urpf_bd_group) {
    modify_field(l3_metadata.urpf_hit, TRUE);
    modify_field(l3_metadata.urpf_bd_group, urpf_bd_group);
    modify_field(l3_metadata.urpf_mode, ipv6_metadata.ipv6_urpf_mode);
}

table ipv6_urpf_lpm {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_sa : lpm;
    }
    actions {
        ipv6_urpf_hit;
        urpf_miss;
    }
    size : IPV6_LPM_TABLE_SIZE;
}

table ipv6_urpf {
    reads {
        l3_metadata.vrf : exact;
        ipv6_metadata.lkp_ipv6_sa : exact;
    }
    actions {
        on_miss;
        ipv6_urpf_hit;
    }
    size : IPV6_HOST_TABLE_SIZE;
}
#endif /* IPV6_DISABLE && URPF_DISABLE */

control process_ipv6_urpf {
#if !defined(IPV6_DISABLE) && !defined(URPF_DISABLE)
    /* unicast rpf lookup */
    if (ipv6_metadata.ipv6_urpf_mode != URPF_MODE_NONE) {
        apply(ipv6_urpf) {
            on_miss {
                apply(ipv6_urpf_lpm);
            }
        }
    }
#endif /* IPV6_DISABLE && URPF_DISABLE */
}
