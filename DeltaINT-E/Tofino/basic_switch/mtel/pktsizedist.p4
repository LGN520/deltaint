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


#define PKTSIZE_AN_INSTANCE_SIZE 16
#define PKTSIZE_AN_INSTANCE_LOG 4
#define PKTSIZE_REGISTER_SIZE 16384 // PKTSIZE_AN_INSTANCE_SIZE * MTEL_NUM_SUMMARIES
#define PKTSIZE_REGISTER_LOG 14   // PKTSIZE_AN_INSTANCE_LOG + MTEL_NUM_SUMMARIES_LOG

header_type pktsize_md_t{
    fields{
        index: PKTSIZE_AN_INSTANCE_LOG;
        len  : 16;
    }
}

metadata pktsize_md_t pktsize_md;

action pktsize_index_set(index){
    modify_field(pktsize_md.index, index);
}

table mtel_pktsize_index{
    reads{
        pktsize_md.len: range;
    }
    actions{
        pktsize_index_set;
    }
    size: 128;  // > PKTSIZE_AN_INSTANCE_SIZE * 3 
}

field_list pktsize_index_lo_hash_fields {
    mtel_md.index;
    pktsize_md.index;
}

field_list_calculation pktsize_index_lo_hash_fields_calc {
    input { pktsize_index_lo_hash_fields; }
    algorithm : identity_lsb;
    output_width : PKTSIZE_REGISTER_LOG;
}

register mtel_pktsize_dist_reg{
    width : 64;  // epoch + bin size
    instance_count : PKTSIZE_REGISTER_SIZE;
    attributes : saturating;
}

blackbox stateful_alu mtel_pktsize_dist_alu{
    reg: mtel_pktsize_dist_reg;

    condition_hi: register_hi != mtel_md.epoch;
    update_lo_2_predicate: condition_hi;
    update_lo_2_value: 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: register_lo + 1;
    update_hi_1_value: mtel_md.epoch;
}

action pktsize_update_run(){
   mtel_pktsize_dist_alu.execute_stateful_alu_from_hash(pktsize_index_lo_hash_fields_calc);
}

table mtel_pktsize_update {
    actions{
        pktsize_update_run;
    }
    default_action:pktsize_update_run;
    size:1;
} 
