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
#ifdef MTEL_ENABLE

#include "least_int.p4"
#include "cms.p4"
#include "pktsizedist.p4"
#include "epoch.p4"
#include "flowsizedist.p4"
#include "drop.p4"

header_type mtel_md_t {
    fields {
        epoch           : 32;
        monitor         : 1;
        index           : MTEL_NUM_SUMMARIES_LOG;
        set_index       : 1;
        flowhash        : 16;
    }
}

metadata mtel_md_t mtel_md;

// to make sure recirculating packets are routed
action mtel_routing_hit(eg_port) {
  modify_field (ig_intr_md_for_tm.ucast_egress_port, eg_port);
  modify_field(ig_intr_md_for_tm.drop_ctl, 0);
}

action mtel_routing_next_pipe_summary(eg_port, m){
    mtel_routing_hit(eg_port);
    add_to_field(mtel_least_int.next_index, m);
}

action mtel_routing_drop(){
    drop();
}

// assuming there are 8 subsummaries and we use all 8
// if we use only n of those we should match on n-1 for next_index,
// reduce n-1 for non-pktgen pipes and add 8-n+1 for pktgen pipe
// valid, set_index, ingress_port     , next_index:
// 0    , x        , recircport       , x         : drop (if stop monitoring) on first pipe
// or
// 0    , x        , recircport       , x         : mtel_routing_hit(same recircport) for first pktgen pkt
// 1    , 1        , recircport_pipe0 , x         : mtel_routing_hit(recurc_pipe1)
// 1    , 1        , recircport_pipe1 , x         : mtel_routing_hit(recurc_pipe2)
// 1    , 1        , recircport_pipe2 , x         : mtel_routing_hit(recurc_pipe3)
// 1    , 1        , recircport_pipe3 , x         : drop 
// 1    , 0        , recircport_pipe0 , 0bxx111   : mtel_routing_next_pipe_summary(recirc_pipe1, -00111)
// 1    , 0        , recircport_pipe1 , 0bxx111   : mtel_routing_next_pipe_summary(recirc_pipe2, -00111)
// 1    , 0        , recircport_pipe2 , 0bxx111   : mtel_routing_next_pipe_summary(recirc_pipe3, -00111)
// 1    , 0        , recircport_pipe3 , 0bxx111   : mtel_routing_next_pipe_summary(recirc_pipe0, 1)
// 1    , 0        , recircport       , x         : mtel_routing_next_pipe_summary(same recircport, 1)

table mtel_late_routing {
    reads {
        mtel_least_int.valid      : exact;
        mtel_md.set_index         : ternary;
        ig_intr_md.ingress_port   : exact;
        mtel_least_int.next_index : ternary;
    }
    actions {
        mtel_routing_hit;
        mtel_routing_next_pipe_summary;
        mtel_routing_drop;
    }
    size: 8;
}

// 8 ports
action port_summary_map_run_8(sub_summary_index, dod){
    modify_field(mtel_md.index, sub_summary_index, 0x7); 
    deflect_on_drop(dod);
#ifdef MTEL_UCOUNTER_ENABLE
    modify_field(ucounter_md.hash_2_m1, sub_summary_index, 0x7);
#endif
}

action port_summary_map_run_16(sub_summary_index, dod){
    modify_field(mtel_md.index, sub_summary_index, 0xF); 
    deflect_on_drop(dod);
#ifdef MTEL_UCOUNTER_ENABLE
    modify_field(ucounter_md.hash_2_m1, sub_summary_index, 0xF);
#endif
}

action port_summary_map_run_32(sub_summary_index, dod){
    modify_field(mtel_md.index, sub_summary_index, 0x1F); 
    deflect_on_drop(dod);
#ifdef MTEL_UCOUNTER_ENABLE
    modify_field(ucounter_md.hash_2_m1, sub_summary_index, 0x1F);
#endif
}

action port_summary_map_run_64(sub_summary_index, dod){
    modify_field(mtel_md.index, sub_summary_index, 0x3F); 
    deflect_on_drop(dod);
#ifdef MTEL_UCOUNTER_ENABLE
    modify_field(ucounter_md.hash_2_m1, sub_summary_index, 0x3F);
#endif
}

action port_summary_map_run_128(sub_summary_index, dod){
    modify_field(mtel_md.index, sub_summary_index, 0x7F); 
    deflect_on_drop(dod);
#ifdef MTEL_UCOUNTER_ENABLE
    modify_field(ucounter_md.hash_2_m1, sub_summary_index, 0x7F);
#endif
}

action port_summary_map_miss(){
    modify_field(mtel_md.monitor, 0);
}

table mtel_port_summary_map {
    reads{
        ig_intr_md_for_tm.ucast_egress_port: exact;
    }
    actions{
        port_summary_map_run_8;
        port_summary_map_run_16;
        port_summary_map_run_32;
        port_summary_map_run_64;
        port_summary_map_run_128;
        port_summary_map_miss;
    }
    default_action: port_summary_map_miss;
    size: 129;  // number of ports+1
}

// ------------------------------------- INGRESS --------------------------

/*
action nop(){
}

control ingress {
  apply(router_mac);
  apply(epoch);
  if (least_int.valid == 1 and
      least_int.start_index == least_int.next_index){
      apply(least_int_finish);
  }
  apply(pktsize_index);
  if (ipv4.valid==1){
      apply(ucounter_hash_1);
      apply(ucounter_hash_2);
#ifndef IPV6_DISABLE
  }else if (ipv6.valid==1){
      apply(ucounter_v6_hash_1);
      apply(ucounter_v6_hash_2);
#endif // IPV6_DISABLE
  }
  apply(epoch_mask);
  apply(ucounter_hash_2_mod_1);
  apply(ucounter_hash_2_mod_2);
  if (least_int.valid == 1){
    apply(epoch_load);
  }else {
    apply(epoch_save);
    apply(ucounter_set_zeros);
    if (mtel_md.monitor == 1){
        apply(port_summary_map);
        if (ipv4.valid==1){
            apply(cms_update_hashtable_1);
            apply(cms_update_hashtable_2);
            apply(cms_update_hashtable_3);
            apply(cms_update_hashtable_4);
#ifndef IPV6_DISABLE
        }else if (ipv6.valid == 1){
            apply(cms_v6_update_hashtable_1);
            apply(cms_v6_update_hashtable_2);
            apply(cms_v6_update_hashtable_3);
            apply(cms_v6_update_hashtable_4);
#endif // IPV6_DISABLE
        }
    }

    if (mtel_md.monitor == 1){ 

        apply(ucounter_update);
        apply(pktsize_update);

        apply(cms_subtract);
        apply(ucounter_hist1_update);

        if (ucounter_md.update_hist != 0){
            apply(ucounter_hist2_update);
        }
        apply(cms_find_min);

        apply(fsd_reg1_index);
        apply(fsd_reg2_index);

        // reg1 never writes into bin 0
        // reg1 bin >= reg2 bin
        if (fsd_md.reg1_bin_index != fsd_md.reg2_bin_index){
            apply(fsd_reg1_update);
        }
    }
  }

  if (least_int.valid == 1 or
        fsd_md.reg2_bin_index != fsd_md.reg1_bin_index and mtel_md.monitor==1){
    apply(fsd_reg2_update);
  }
}


// -------------------------------------- EGRESS --------------------------

control egress {
    if (ethernet.etherType == ETHERTYPE_BF_PKTGEN){
        apply(least_int_start);
    }else{
      if (least_int.valid==1 or 
         eg_intr_md.deflection_flag == 1 and mtel_md.monitor==1){
        apply(drop_reg_update); 
      }
      if (least_int.valid==1 and mtel_md.set_index == 0){
        apply(least_int_add);
      }
    }
}
*/

#endif // MTEL_ENABLE
