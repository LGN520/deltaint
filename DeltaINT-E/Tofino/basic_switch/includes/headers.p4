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
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type llc_header_t {
    fields {
        dsap : 8;
        ssap : 8;
        control_ : 8;
    }
}

header_type snap_header_t {
    fields {
        oui : 24;
        type_ : 16;
    }
}

header_type roce_header_t {
    fields {
        ib_grh : 320;
        ib_bth : 96;
    }
}

header_type roce_v2_header_t {
    fields {
        ib_bth : 96;
    }
}

header_type fcoe_header_t {
    fields {
        version : 4;
        type_ : 4;
        sof : 8;
        rsvd1 : 32;
        ts_upper : 32;
        ts_lower : 32;
        size_ : 32;
        eof : 8;
        rsvd2 : 24;
    }
}

header_type fcoe_fc_header_t {
    fields {
        version : 4;
        reserved : 100;
        sof : 8;
        r_ctl : 8;
        d_id : 24;
        cs_ctl : 8;
        s_id : 24;
        type_ : 8;
        f_ctl : 24;
        seq_id : 8;
        df_ctl : 8;
        seq_cnt : 16;
        ox_id : 16;
        rx_id : 16;
    }
}

header_type fip_header_t {
    fields {
        version : 4;
        rsvd : 12;
        oper_code : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 12;
        etherType : 16;
    }
}

header_type ieee802_1ah_t {
    fields {
        pcp : 3;
        dei : 1;
        uca : 1;
        reserved : 3;
        i_sid : 24;
    }
}

header_type mpls_t {
    fields {
        label : 20;
        exp : 3;
        bos : 1;
        ttl : 8;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16 (saturating);
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type ipv4_option_32b_t {
  fields { option_fields : 32; }
}
                        
header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16 (saturating);
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

header_type icmp_t {
    fields {
        typeCode : 16;
        hdrChecksum : 16;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
#ifndef TCP_HEADER_OPTIMIZATION_ENABLE
        window : 16;
        checksum : 16;
        urgentPtr : 16;
#endif /* TCP_HEADER_OPTIMIZATION_ENABLE */
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16 (saturating);
        checksum : 16;
    }
}

// First 32-bits of IGMP header
header_type igmp_t {
    fields {
        typeCode : 16;
        hdrChecksum : 16;
    }
}

// for DTel watchlist, avoid additional metadata to unify udp and tcp ports
header_type inner_l4_ports_t {
    fields {
        srcPort : 16;
        dstPort : 16;
    }
}

// for DTel report triggering, parsed after inner_l4_ports
header_type inner_tcp_info_t {
    fields {
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type sctp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        verifTag : 32;
        checksum : 32;
    }
}

header_type gre_t {
    fields {
        C : 1;
        R : 1;
        K : 1;
        S : 1;
        s : 1;
        recurse : 3;
        flags : 5;
        ver : 3;
        proto : 16;
    }
}

header_type nvgre_t {
    fields {
        tni : 24;
        flow_id : 8;
    }
}

/* erspan III header - 12 bytes */
header_type erspan_header_t3_t {
    fields {
        version : 4;
        vlan : 12;
        priority_span_id : 16;
        timestamp : 32;
        ft_d_other: 32;
/*  ft_d_other_sgt aggregates next fields:
        sgt       : 16;
        pdu_frame        : 1;
        frame_type       : 5;
        hw_id            : 6;
        direction        : 1; // ingress (0) or egress (1)
        granularity      : 2;
        optional_sub_hdr : 1;
*/
    }
}

header_type ipsec_esp_t {
    fields {
        spi : 32;
        seqNo : 32;
   }
}

header_type ipsec_ah_t {
    fields {
        nextHdr : 8;
        length_ : 8;
        zero : 16;
        spi : 32;
        seqNo : 32;
    }
}

header_type arp_rarp_t {
    fields {
        hwType : 16;
        protoType : 16;
        hwAddrLen : 8;
        protoAddrLen : 8;
        opcode : 16;
    }
}

header_type arp_rarp_ipv4_t {
    fields {
        srcHwAddr : 48;
        srcProtoAddr : 32;
        dstHwAddr : 48;
        dstProtoAddr : 32;
    }
}

header_type eompls_t {
    fields {
        zero : 4;
        reserved : 12;
        seqNo : 16;
    }
}

header_type vxlan_t {
    fields {
        flags : 8;
        reserved : 24;
        vni : 24;
        reserved2 : 8;
    }
}

header_type vxlan_gpe_t {
    fields {
        flags : 8;
        reserved : 16;
        next_proto : 8;
        vni : 24;
        reserved2 : 8;
    }
}

header_type nsh_t {
    fields {
        oam : 1;
        context : 1;
        flags : 6;
        reserved : 8;
        protoType: 16;
        spath : 24;
        sindex : 8;
    }
}

header_type nsh_context_t {
    fields {
        network_platform : 32;
        network_shared : 32;
        service_platform : 32;
        service_shared : 32;
    }
}


/* GENEVE HEADERS
   3 possible options with known type, known length */

header_type genv_t {
    fields {
        ver : 2;
        optLen : 6;
        oam : 1;
        critical : 1;
        reserved : 6;
        protoType : 16;
        vni : 24;
        reserved2 : 8;
    }
}

#define GENV_OPTION_A_TYPE 0x000001
/* TODO: Would it be convenient to have some kind of sizeof macro ? */
#define GENV_OPTION_A_LENGTH 2 /* in bytes */

header_type genv_opt_A_t {
    fields {
        optClass : 16;
        optType : 8;
        reserved : 3;
        optLen : 5;
        data : 32;
    }
}

#define GENV_OPTION_B_TYPE 0x000002
#define GENV_OPTION_B_LENGTH 3 /* in bytes */

header_type genv_opt_B_t {
    fields {
        optClass : 16;
        optType : 8;
        reserved : 3;
        optLen : 5;
        data : 64;
    }
}

#define GENV_OPTION_C_TYPE 0x000003
#define GENV_OPTION_C_LENGTH 2 /* in bytes */

header_type genv_opt_C_t {
    fields {
        optClass : 16;
        optType : 8;
        reserved : 3;
        optLen : 5;
        data : 32;
    }
}

header_type trill_t {
    fields {
        version : 2;
        reserved : 2;
        multiDestination : 1;
        optLength : 5;
        hopCount : 6;
        egressRbridge : 16;
        ingressRbridge : 16;
    }
}

header_type lisp_t {
    fields {
        flags : 8;
        nonce : 24;
        lsbsInstanceId : 32;
    }
}

header_type vntag_t {
    fields {
        direction : 1;
        pointer : 1;
        destVif : 14;
        looped : 1;
        reserved : 1;
        version : 2;
        srcVif : 12;
    }
}

header_type bfd_t {
    fields {
        version : 3;
        diag : 5;
        state_flags : 8;
        /*
         * state : 2;
         * p : 1;
         * f : 1;
         * c : 1;
         * a : 1;
         * d : 1;
         * m : 1;
         */
        detectMult : 8;
        len : 8;
        myDiscriminator : 32;
        yourDiscriminator : 32;
        desiredMinTxInterval : 32;
        requiredMinRxInterval : 32;
        requiredMinEchoRxInterval : 32;
    }
}

header_type sflow_hdr_t {
    fields {
        version : 32;
        addrType : 32;
        ipAddress : 32;
        subAgentId : 32;
        seqNumber : 32;
        uptime : 32;
        numSamples : 32;
    }
}

header_type sflow_sample_t {
    fields {
        enterprise : 20;
        format : 12;
        sampleLength : 32;
        seqNumer : 32;
        srcIdType : 8;
        srcIdIndex : 24;
        samplingRate : 32;
        samplePool : 32;
        numDrops : 32;
        inputIfindex : 32;
        outputIfindex : 32;
        numFlowRecords : 32;
    }
}

header_type sflow_raw_hdr_record_t {
    // this header is attached to each pkt sample (flow_record)
    fields {
        enterprise          : 20;
        format              : 12;
        flowDataLength_hi   : 16;    // order reversed with protocol?
        flowDataLength      : 16;    // order reversed with protocol?
        headerProtocol      : 32;
        frameLength_hi      : 16;
        frameLength         : 16;
        bytesRemoved_hi     : 16;
        bytesRemoved        : 16;
        headerSize_hi       : 16;    // not sure what len is this - not in spec?
        headerSize          : 16;    // not sure what len is this - not in spec?
    }
}


header_type sflow_sample_cpu_t {
    fields {
        sampleLength        : 16;
        samplePool          : 32;
        inputIfindex        : 16;
        outputIfindex       : 16;
        numFlowRecords      : 8;
        sflow_session_id    : 3;
        pipe_id             : 2;
    }
}

#define FABRIC_HEADER_TYPE_NONE        0
#define FABRIC_HEADER_TYPE_UNICAST     1
#define FABRIC_HEADER_TYPE_MULTICAST   2
#define FABRIC_HEADER_TYPE_MIRROR      3
#define FABRIC_HEADER_TYPE_CONTROL     4
#define FABRIC_HEADER_TYPE_CPU         5

header_type fabric_header_t {
    fields {
        packetType : 3;
        headerVersion : 2;
        packetVersion : 2;
        mcast : 1;

#ifdef CPU_TX_TC_QUEUE_ENABLE
        egressTc : 8;
#else
        fabricColor : 3;
        fabricQos : 5;
#endif /* CPU_TX_TC_QUEUE_ENABLE */

        dstDevice : 8;
        dstPortOrGroup : 16;
    }
}

header_type fabric_header_unicast_t {
    fields {
        routed : 1;
        outerRouted : 1;
        tunnelTerminate : 1;
        ingressTunnelType : 5;

        nexthopIndex : 16;
    }
}

header_type fabric_header_multicast_t {
    fields {
        routed : 1;
        outerRouted : 1;
        tunnelTerminate : 1;
        ingressTunnelType : 5;

        ingressIfindex : 16;
        ingressBd : 16;

        mcastGrpA : 16;
        mcastGrpB : 16;
        ingressRid : 16;
        l1ExclusionId : 16;
    }
}

header_type fabric_header_mirror_t {
    fields {
        rewriteIndex : 16;
        egressPort : 10;
        egressQueue : 5;
        pad : 1;
    }
}


#ifdef FABRIC_HEADER_OPTIMIZATION_ENABLE
header_type fabric_header_cpu_t {
    fields {
        egressQueue : 5;
        txBypass : 1;
        capture_tstamp_on_tx : 1;
        dtelIntPresent: 1;

        dstPortOrGroup : 16;
        ingressPort: 16;
        ingressIfindex : 16;
        ingressBd : 16;
        reasonCode : 16;
    }
}
#else
header_type fabric_header_cpu_t {
    fields {
#ifdef CPU_TX_TC_QUEUE_ENABLE
        txBypass : 1;
        egressQueue : 5;
#else
        egressQueue : 5;
        txBypass : 1;
#endif /* CPU_TX_TC_QUEUE_ENABLE */
        capture_tstamp_on_tx : 1;
        dtelIntPresent: 1;

        ingressPort: 16;
        ingressIfindex : 16;
        ingressBd : 16;

        reasonCode : 16;
    }
}
#endif /* FABRIC_HEADER_OPTIMIZATION_ENABLE */

header_type fabric_header_timestamp_t {
  fields {
      arrival_time_hi : 16;
      arrival_time    : 32;
  }
}

header_type fabric_header_sflow_t {
    fields {
        sflow_session_id  : 16;
    }
}

header_type fabric_header_bfd_event_t {
    fields {
        bfd_session_id  : 16;
        bfd_event_id  : 16; // e.g timeout, remote param change..
    }
}

header_type fabric_payload_header_t {
    fields {
        etherType : 16;
    }
}

// INT headers
header_type int_header_t {
    fields {
        ver                     : 4;
        rep                     : 2;
        c                       : 1;
        e                       : 1;
        d                       : 1;
        rsvd1                   : 2;
        ins_cnt                 : 5;
        max_hop_cnt             : 8;
        total_hop_cnt           : 8;
        instruction_bitmap_0003 : 4;   // split the bits for lookup
        instruction_bitmap_0407 : 4;
        instruction_bitmap_0811 : 4;
        instruction_bitmap_1215 : 4;
        rsvd2_digest            : 16;
    }
}
// INT meta-value headers - different header for each value type
header_type int_switch_id_header_t {
    fields {
        switch_id           : 32;
    }
}
header_type int_port_ids_header_t {
    fields {
        pad_1               : 7;
        ingress_port_id     : 9;
        egress_port_id      : 16;
    }
}
header_type int_ingress_port_id_header_t {
    fields {
        ingress_port_id_1   : 16;
        ingress_port_id_0   : 16;
    }
}
header_type int_hop_latency_header_t {
    fields {
        hop_latency         : 32;
    }
}
header_type int_q_occupancy_header_t {
    fields {
        rsvd                : 3;
        qid                 : 5;
        q_occupancy0        : 24;
    }
}
header_type int_ingress_tstamp_header_t {
    fields {
        ingress_tstamp      : 32;
    }
}
header_type int_egress_port_id_header_t {
    fields {
        egress_port_id      : 32;
    }
}
header_type int_egress_tstamp_header_t {
    fields {
        egress_tstamp       : 32;
    }
}
header_type int_q_congestion_header_t {
    fields {
        q_congestion        : 32;
    }
}
header_type int_egress_port_tx_utilization_header_t {
    fields {
        egress_port_tx_utilization  : 32;
    }
}

// generic int value (info) header for extraction
header_type int_value_t {
    fields {
        val         : 32;
    }
}

header_type intl45_marker_header_t {
    fields {
        f0 : 32;
        f1 : 32;
    }
}

header_type intl45_head_header_t {
    fields {
        int_type    :8;
        len         :16;
        rsvd1       :8;
    }
}

// Based on draft-ietf-6man-segment-routing-header-15
header_type ipv6_srh_t {
    fields {
        nextHdr : 8;
        hdrExtLen : 8;
        routingType : 8;
        segLeft : 8;
        lastEntry : 8;
        flags : 8;
        tag : 16;
    }
}

header_type ipv6_srh_segment_t {
    fields {
        sid : 128;
    }
}

header_type dtel_report_header_t {
    fields {
/*
        version             : 4;
        next_proto          : 4;
        dropped             : 1;
        congested_queue     : 1;
        path_tracking_flow  : 1;
        reserved1           : 5;
        reserved2           : 10;
        hw_id               : 6;
*/
        merged_fields       : 32;
        sequence_number     : 32;
        timestamp           : 32;
    }
}

header_type postcard_header_t {
    fields {
        switch_id           : 32;
        ingress_port        : 16;
        egress_port         : 16;
        queue_id            : 8;
        queue_depth         : 24;
        egress_tstamp       : 32;
    }
}

header_type mirror_on_drop_header_t {
    fields {
        switch_id           : 32;
        ingress_port        : 16;
        egress_port         : 16;
        queue_id            : 8;
        drop_reason         : 8;
        pad                 : 16;
    }
}

#ifdef COLEASED_MIRROR_ENABLE
header_type coal_pkt_hdr_t {
    // Internal header used for coalesced packet
    // must be multiple of 4 bytes.
    // First two bytes, num_samples and internal parser byte are
    // assumed to be removed already by the parser
    fields {
        session_id : 16;
    }
}
#endif

#ifdef PKTGEN_ENABLE
header_type pktgen_ext_header_t {
    /*
     * pktgen_ext_header contains 6bytes of pad and 2bytes on ethType
     * This size must match standard ethernet frame's mac_sa nd ethType
     * so that parser can demux pktgen pkt from regular ethernet pkt
     */
    fields {
        pad : 48;
        etherType : 16;
    }
}
#endif /* PKTGEN_ENABLE */

#define CPU_REASON_CODE_BFD_EVENT   0x108 /* must match switch_hostif.h reson_code */

#ifdef MTEL_ENABLE
// update header per update of MTEL_NUM_SUMMARIES_LOG
header_type mtel_least_int_t {
    fields {
        pad1 :  MTEL_NUM_SUMMARIES_LOG_16;
        index : MTEL_NUM_SUMMARIES_LOG;
        pad2 :  MTEL_NUM_SUMMARIES_LOG_16;
        start_index :  MTEL_NUM_SUMMARIES_LOG;
        pad3 :  MTEL_NUM_SUMMARIES_LOG_16;
        next_index : MTEL_NUM_SUMMARIES_LOG;
        pad4 :  MTEL_NUM_SUMMARIES_LOG_16;
        old_index : MTEL_NUM_SUMMARIES_LOG;
        value : 32;
        prev_value: 32;
        read_value: 32;
    }
}
#endif // MTEL_ENABLE
