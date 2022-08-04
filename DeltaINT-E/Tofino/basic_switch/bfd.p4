#ifdef BFD_OFFLOAD_ENABLE

#define BFD_PKT_ACTION_NORMAL   0x00
#define BFD_PKT_ACTION_TIMEOUT  0x01
#define BFD_PKT_ACTION_DROP     0x02
#define BFD_PKT_ACTION_INVALID  0x03

/* BYPASS_L2,BYPASS_ACL, BYPASS_PKT_VALIDATION, BYPASS_SMAC_CHK */
#define BFD_TX_BYPASS_FLAGS     0xC5

header_type bfd_meta_t {
    fields {
        tx_mult : 8;
        rx_mult : 8;
        pkt_action : 2;
        pktgen_pipe : 3;    /* 0 is reserved */
        tx_timer_expired : 1;
        session_id : 10;
        session_offload : 1;
        rx_recirc: 1;
        pkt_tx : 1;
    }
}
metadata bfd_meta_t bfd_meta;

register bfd_tx_session_counter {
    /*
     * register to detect bfd tx interval for a session
     * pktgen timer is a sub-multiple of negotiated tx timer for each
     * session.
     */
    width: 8;
    instance_count: BFD_TX_TIMER_TABLE_SIZE;
}

blackbox stateful_alu bfd_tx_timer {
    reg: bfd_tx_session_counter;

    /*
     * increment register
     * output TRUE when the register hits_tx_mult for that session
     * reset register to 0 when it hits tx_mult
     */
    condition_lo: register_lo < bfd_meta.tx_mult;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo+1;

    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: 0;

    output_predicate: not condition_lo;
    output_value: predicate;
    output_dst: bfd_meta.tx_timer_expired;
}

register bfd_rx_session_timer {
    /*
     * register value -
     *   0 => reserved to indicate no-offload,
     *   1 => rx timeout,
     *  >1 => remaining rx multiplier
     */
    width: 8;
    instance_count: MAX_BFD_SESSIONS_PER_PIPE;
}

blackbox stateful_alu bfd_rx_session_reset {
    reg: bfd_rx_session_timer;

    condition_lo: register_lo == 0;   /* 0x00 = no offload */

    /*
     * reset the detection multiplier count to session's detectMult,
     * if offload is in effect
     */
    update_lo_1_predicate: not condition_lo;
    update_lo_1_value: bfd_meta.rx_mult;

}

blackbox stateful_alu bfd_rx_session_check {
    reg: bfd_rx_session_timer;

    condition_lo: register_lo == 0x00;   /* 0x00 = no offload */
    condition_hi: register_lo == 1;      /* timeout */

    /* decrement the counter if offload is in effect */
    update_lo_1_predicate: not condition_lo;
    update_lo_1_value: register_lo - 1;

    /*
     * This is an 8 bit register, the hi_1/2 values are
     * computed but not written back to the register, instead
     * alu_hi_1/2 outputs are OR-ed together and used as an output
     */
    update_hi_1_predicate: condition_hi;
    update_hi_1_value: 1; /* timeout  - bit 0 */

    update_hi_2_predicate: condition_lo;
    update_hi_2_value: 2; /* no offload  - bit 1 */

    /*
     * alu_hi values indicate -'b00=Normal, 'b01=timeout, 'b10=drop, 'b11=NA
     * timeout and drop actions are encoded by the two conditions.
     * output 0 when both conditions are false - this is done by predicating the
     * output as below
     */
    output_predicate: condition_lo or condition_hi;
    output_dst: bfd_meta.pkt_action;
    output_value: alu_hi;
}

action bfd_pkt_to_cpu(cpu_mirror_id, reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
    modify_field(i2e_metadata.mirror_session_id, cpu_mirror_id);
    clone_ingress_pkt_to_egress(cpu_mirror_id, bfd_cpu_info);
    drop(); /* pkt to cpu used i2e mirroring, drop the orignal pkt */
}

action bfd_recirc_to_pktgen_pipe() {
    /*
     * pktgen_pipe is already set, use it to skip the rest of the ingress
     * and egress pipelines
     * set egress port for TM
     */
    modify_field(bfd_meta.rx_recirc, 1);
#ifdef __TARGET_TOFINO__
    exit();    /* skip the rest of the pipeline */
#endif
}

action bfd_tx_pkt() {
    /* let the pipeline take care of routing the packet */
}

table bfd_pkt_action {
    reads {
        /*
         * offload is a GW condition before executing this table
         * offload  pkt_tx  pkt_action  pktgen_pipe action
         *    0     X       X           X           N/A
         *    1     0       0           this_pipe   drop (do not use default)
         *    1     0       0           X           recirc - !this_pipe
         *    1     0       1           X           nop
         *    1     1       0           X           bfd_tx_pkt
         *    1     1       1           X           to_cpu (timeout)
         *          all the rest - drop
         */
        bfd_meta.pkt_tx : exact;
        bfd_meta.pkt_action : exact;
        /* pktgen_pipe key value is the pipe_id where the entry is programmed */
        bfd_meta.pktgen_pipe : ternary;
    }
    actions {
        bfd_pkt_to_cpu;
        bfd_recirc_to_pktgen_pipe;
        bfd_tx_pkt;             /* => send the bfd pkt out */
        bfd_drop_pkt;   /* default action */
        nop;
    }
    size : 8;
}

action bfd_drop_pkt() {
    drop();
}

action bfd_rx_timer_reset(local_session_id) {
    bfd_rx_session_reset.execute_stateful_alu(local_session_id);
}

action bfd_tx_add_ipv4(sip, dip) {
    modify_field(ipv4.srcAddr, sip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(ipv4_metadata.lkp_ipv4_sa, sip);
    modify_field(ipv4_metadata.lkp_ipv4_da, dip);
    modify_field(l3_metadata.lkp_ip_proto, ipv4.protocol);
    modify_field(l3_metadata.lkp_ip_ttl, ipv4.ttl);
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, 1);
}

action bfd_tx_add_udp(sport, dport) {
    modify_field(udp.srcPort, sport);
    modify_field(udp.dstPort, dport);
    modify_field(l3_metadata.lkp_l4_sport, sport);
    modify_field(l3_metadata.lkp_l4_dport, dport);
}

action bfd_session_ipv4(sip, dip, sport, dport) {
    bfd_tx_add_ipv4(sip, dip);
    bfd_tx_add_udp(sport, dport);
}

action bfd_rx_timer_check(local_session_id, sip, dip, sport, dport) {
    /* check rx timer to see if session has timedout */
    bfd_rx_session_check.execute_stateful_alu(local_session_id);
    /* get session routing info - sip, dip, sport, dport */
    bfd_session_ipv4(sip, dip, sport, dport);
    modify_field(ig_intr_md_for_tm.mcast_grp_a, 0);
    modify_field(l2_metadata.lkp_mac_sa, ethernet.srcAddr);
    modify_field(l2_metadata.lkp_mac_da, ethernet.dstAddr);
}



table bfd_rx_timers {
    /*
     * used by both tx and rx frames to check and reset the timer respectively
     * only the sessions that are handled on a given pipe need to be programmed
     */
    reads {
        /*
         * offload  pkt_tx  session_id  action
         *  0       X       X           nop (default)
         *  1       0       id          timer_reset
         *  1       1       id          timer_check
         */
        bfd_meta.session_offload : exact;
        bfd_meta.pkt_tx : exact;    /*  differentiate rx and tx */
        bfd_meta.session_id : exact;
    }
    actions {
        bfd_rx_timer_reset;     /*  used for rx pkt */
        bfd_rx_timer_check;     /*  used for tx pkt (v4 info) */
        nop;
    }
    size : MAX_BFD_SESSIONS_PER_PIPE_2X;  /*  double the size due to rx and tx */
}

field_list bfd_cpu_info {
    cpu_info;
    bfd_meta.session_id;
    i2e_metadata.mirror_session_id;
}

action bfd_session_miss() {
}

action bfd_update_rx_session_info(session_id, rx_mult, pktgen_pipe,
                                  recirc_port) {
    bfd_update_session_info(session_id, rx_mult);
    modify_field(bfd_meta.pktgen_pipe, pktgen_pipe);
    /*  egress port is set here, once recirc is determined, this must not be */
    /*  modified by rest of the pipeline */
    modify_field(ig_intr_md_for_tm.ucast_egress_port, recirc_port);
    modify_field(bfd_meta.session_offload, 1);
}

table bfd_rx_session {
    /*
     * rx_sessions are programmed on all pipes since rx packet can be received
     * on any port(pipe)
     * This provides session_id, rx_timer and pipe where this session is managed
     * table miss indicates that the session is not offloaded or the bfd packet
     * is a transit bfd packet. BFD pkt will be sent to local CPU based on dest
     * ip addr or routed to correct destination later in the pipeline
     */
    reads {
        bfd_header : valid;
        bfd_header.myDiscriminator : exact;
        bfd_header.yourDiscriminator : exact;
        /*  More fields like timer vals, flags to detect any change */
        bfd_header.version : exact;
        bfd_header.state_flags : exact; /* must be 0xC0 */
        bfd_header.desiredMinTxInterval : exact;
        bfd_header.requiredMinRxInterval : exact;
    }
    actions {
        bfd_update_rx_session_info;
        bfd_session_miss;
    }
    size : MAX_BFD_SESSIONS;
}

action bfd_update_session_info(session_id, rx_mult) {
    modify_field(bfd_meta.rx_mult, rx_mult); /* multipliers wrt pktgen timer */
    modify_field(bfd_meta.session_id, session_id);
}

action bfd_tx_add_eth_header(rmac) {
    add_header(ethernet);
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
    modify_field(ethernet.dstAddr, rmac);
    modify_field(ethernet.srcAddr, rmac);
    remove_header(pktgen_generic);
    remove_header(pktgen_ext_header);
}

action bfd_update_tx_session_info(session_id, rx_mult, tx_mult, vrf,
                                  rmac_group, rmac) {
    bfd_update_session_info(session_id, rx_mult);
    modify_field(bfd_meta.tx_mult, tx_mult); /* multipliers wrt pktgen timer */
    modify_field(bfd_meta.session_offload, 1);
    bfd_tx_add_eth_header(rmac);
    modify_field(l3_metadata.vrf, vrf);
    modify_field(l3_metadata.rmac_group, rmac_group);
    modify_field(l2_metadata.lkp_mac_da, rmac);
    modify_field(bfd_meta.pkt_action, BFD_PKT_ACTION_INVALID); /* for debug */
    modify_field(ingress_metadata.bypass_lookups, BFD_TX_BYPASS_FLAGS);
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
}

action bfd_tx_drop_pkt() {
    modify_field(bfd_meta.pkt_action, BFD_PKT_ACTION_DROP);
    drop();
}

table bfd_tx_session {
    /*
     * provides session_id and tx_timer value for the session that is
     *  handled on this pipe
     *  if session is not handled on this pipe, drop
     */
    reads {
        /* use packet id to find the bfd session */
        /* XXX - use diff app_id for ipv6 - batch id will not work */
        pktgen_generic.app_id : exact;
        pktgen_generic.packet_id : exact;
    }
    actions {
        bfd_tx_drop_pkt;   /* default action */
        bfd_update_tx_session_info;
    }
    size : MAX_BFD_SESSIONS_PER_PIPE;
}

control process_bfd_tx_packet {
    /* build the bfd packet and get other session info */
    apply(bfd_tx_session);
}
control process_bfd_rx_packet {
    apply(bfd_rx_session);
}
control process_bfd_packet {
    if (bfd_meta.session_offload == TRUE) {
        apply(bfd_rx_timers);
        apply(bfd_pkt_action);
    }
}


/* === Egress Processing === */

action bfd_send_pkt() {
}

action bfd_tx_update_bfd_header(myDisc, yourDisc, minTx, minRx, detectMult) {
    modify_field(bfd_header.myDiscriminator, myDisc);
    modify_field(bfd_header.yourDiscriminator, yourDisc);
    modify_field(bfd_header.detectMult, detectMult);
    modify_field(bfd_header.desiredMinTxInterval, minTx);
    modify_field(bfd_header.requiredMinRxInterval, minRx);
    /* XXX minRxInterval is used as Echo.. use different val */
    modify_field(bfd_header.requiredMinEchoRxInterval, minRx);
}

action bfd_tx_update_ipv4(myDisc, yourDisc, minTx, minRx, detectMult) {
    /*
     * bfd_1hop needs ttl to be 255
     * It is deceremented later by ipv4_unicast_rewrite()
     */
    modify_field(ipv4.ttl, 0);
    bfd_tx_update_bfd_header(myDisc, yourDisc, minTx, minRx, detectMult);
}

action bfd_tx_timer_check(session_id, myDisc, yourDisc, minTx, minRx, detectMult) {
    bfd_tx_timer.execute_stateful_alu(session_id);
    bfd_tx_update_ipv4(myDisc, yourDisc, minTx, minRx, detectMult);
}

table bfd_tx_timer {
    /*
     * Two types of packets need to be handled on the egress pipeline -
     *  - bfd rx packets that need to be sent to correct pipe
     *  - bfd tx packets after checking the tx timer
     *
     *  pkt_tx  pkt_action   session_id  action
     *  0       X           X            NA
     *  1       00           session_id  tx_timer_check
     *  everything else - default - drop
     */
    reads {
        bfd_meta.pkt_tx : exact;
        bfd_meta.pkt_action : exact;
        bfd_meta.session_id : ternary; /* not used for rx */
    }
    actions {
        bfd_tx_timer_check;
        bfd_drop_pkt;   /* default */
    }
    size : BFD_TX_TIMER_TABLE_SIZE;
}

action bfd_tx_egress_drop() {
    drop();
}

table bfd_tx_timer_action {
    actions {
        bfd_tx_egress_drop; /* default */
    }
    default_action : bfd_tx_egress_drop;
    size : 1;
}

action bfd_tx_to_cpu() {
    add_header(ethernet);
    modify_field(ethernet.dstAddr, 0);
    modify_field(ethernet.srcAddr, 0);
    modify_field(ethernet.etherType, pktgen_ext_header.etherType);
    remove_header(pktgen_generic);
    remove_header(pktgen_ext_header);
    add_header(fabric_header_bfd);
    modify_field(fabric_header_bfd.bfd_session_id, bfd_meta.session_id);
    modify_field(fabric_header_bfd.bfd_event_id, 0);
}

table bfd_fix_pkt_hdrs {
    reads {
        bfd_meta.pkt_tx : exact;
    }
    actions {
        bfd_tx_to_cpu; /* default */
    }
    size : 1;
}

action bfd_recirc_skip_egress() {
#ifdef __TARGET_TOFINO__
    /*  just send to a specific recirc port no other processing is needed */
    exit();
#endif
}

table bfd_recirc_egress {
    actions {
        bfd_recirc_skip_egress; /* exit the egress pipeline */
    }
    default_action : bfd_recirc_skip_egress;
    size : 1;
}

control process_bfd_recirc {
    if (bfd_meta.rx_recirc != 0) {
        apply(bfd_recirc_egress);
    }
}

control process_egress_bfd_packet {
    if ((bfd_meta.session_offload == TRUE) and (bfd_meta.pkt_tx != 0)) {
        apply(bfd_tx_timer);
        if (bfd_meta.tx_timer_expired == FALSE) {
            /* drop the packet if timer to send has not expired */
            apply(bfd_tx_timer_action);
        }
    }
}

control process_bfd_mirror_to_cpu {
    apply(bfd_fix_pkt_hdrs);
}

#ifdef BFD_DEBUG
/* use this table to print (log) required meta-data values for debug */
table bfd_debug_table {
    reads {
        bfd_meta.session_id : exact;
        bfd_meta.session_offload : exact;
        bfd_meta.tx_mult : exact;
        bfd_meta.tx_timer_expired : exact;
    }
    actions {
        nop;
    }
    size : 1;
}

control process_bfd_debug {
    apply(bfd_debug_table);
}
#endif /* BFD_DEBUG */

#else

/* stubs when bfd offload is not enabled */
control process_bfd_mirror_to_cpu {
}
control process_egress_bfd_packet {
}
control process_egress_bfd_tx_timers {
}
control process_bfd_packet {
}
control process_bfd_rx_packet {
}
control process_bfd_tx_packet {
}
control process_bfd_recirc {
}
#endif /* BFD_OFFLOAD_ENABLE */
