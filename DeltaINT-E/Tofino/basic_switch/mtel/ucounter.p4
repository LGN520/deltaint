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
 * A general data structure to count the number of unique items
 * in data plane based on hyperloglog algorithm
 *
 */
#define UCOUNTER_HASH_LEN_1    32
#define UCOUNTER_HASH_LEN_2    32
#define UCOUNTER_RANGE_2       4294967296
#define UCOUNTER_RANGE_1       4294967296

#define UCOUNTER_NUM            16384     // number of counters (WIDTH=log(num))
#define UCOUNTER_LOGLOG         5        // # bit required to save (# zeros +1) in hash 1
// lets keep # zeros in 5 bit (treat hash = 0 the same as hash = 1)
#define REGISTER_INSTANCES      UCOUNTER_NUM     // UCOUNTER_NUM
#define UCOUNTER_HIST_SIZE_LOG  14        // UCOUNTER_LOGLOG + MTEL_NUM_SUMMARIES_LOG
#define UCOUNTER_HIST_SIZE      16384     // 2^ UCOUNTER_HIST_SIZE_LOG 

header_type ucounter_md_t {
    fields {
        hash_1 : UCOUNTER_HASH_LEN_1;
        hash_2 : UCOUNTER_HASH_LEN_2; 
        hash_2_m1 : 16; 
        hash_2_m2 : 16; 
        zeros  : UCOUNTER_LOGLOG;    // # zeros before first msb 1 + 1
        old_zeros : UCOUNTER_LOGLOG;
        update_hist : 1;
    }
}

metadata ucounter_md_t ucounter_md;

field_list_calculation ucounter_hash_1 {
    input { lkp_ipv4_hash1_fields; }
    algorithm : crc32;
    output_width : UCOUNTER_HASH_LEN_1; 
}

field_list_calculation ucounter_hash_2 {
    input { lkp_ipv4_hash1_fields; }
    algorithm : crc_32c;
    output_width : UCOUNTER_HASH_LEN_2;
}

field_list_calculation ucounter_v6_hash_1 {
    input { lkp_ipv6_hash1_fields; }
    algorithm : crc32;
    output_width : UCOUNTER_HASH_LEN_1; 
}

field_list_calculation ucounter_v6_hash_2 {
    input { lkp_ipv6_hash1_fields; }
    algorithm : crc_32c;
    output_width : UCOUNTER_HASH_LEN_2;
}

action ucounter_calculate_hash_2() {
    modify_field_with_hash_based_offset(ucounter_md.hash_2, 0, 
                                        ucounter_hash_2, UCOUNTER_RANGE_2);
}

action ucounter_calculate_hash_1() {
    modify_field_with_hash_based_offset(ucounter_md.hash_1, 0, 
                                        ucounter_hash_1, UCOUNTER_RANGE_1);
}

table mtel_ucounter_hash_1 {
    actions { ucounter_calculate_hash_1; }
    default_action: ucounter_calculate_hash_1;
    size:1;
}

table mtel_ucounter_hash_2 {
    actions { ucounter_calculate_hash_2; }
    default_action:ucounter_calculate_hash_2;
    size:1;
}

action ucounter_calculate_v6_hash_2() {
    modify_field_with_hash_based_offset(ucounter_md.hash_2, 0, 
                                        ucounter_v6_hash_2, UCOUNTER_RANGE_2);
}

action ucounter_calculate_v6_hash_1() {
    modify_field_with_hash_based_offset(ucounter_md.hash_1, 0, 
                                        ucounter_v6_hash_1, UCOUNTER_RANGE_1);
}

table mtel_ucounter_v6_hash_1 {
    actions { ucounter_calculate_v6_hash_1; }
    default_action: ucounter_calculate_v6_hash_1;
    size:1;
}

table mtel_ucounter_v6_hash_2 {
    actions { ucounter_calculate_v6_hash_2; }
    default_action: ucounter_calculate_v6_hash_2;
    size:1;
}

action ucounter_hash_2_mod_1_run(mod){
    modify_field(ucounter_md.hash_2_m1, mod);
}

table mtel_ucounter_hash_2_mod_1 {
    reads {
        ucounter_md.hash_2 mask 0xFFFF0000: exact;
    }
    actions{
        ucounter_hash_2_mod_1_run;
    }
    default_action: ucounter_hash_2_mod_1_run(0);
    size: 65536;
}

action ucounter_hash_2_mod_2_run(mod){
    modify_field(ucounter_md.hash_2_m2, mod);
}

table mtel_ucounter_hash_2_mod_2 {
    reads {
        ucounter_md.hash_2 mask 0xFFFF: exact;
    }
    actions{
        ucounter_hash_2_mod_2_run;
    }
    default_action: ucounter_hash_2_mod_2_run(0);
    size: 65536;
}

action ucounter_set_zeros(zeros) {
    modify_field(ucounter_md.zeros, zeros);
    add_to_field(ucounter_md.hash_2_m1, ucounter_md.hash_2_m2);
}

// give the number of zeros before finding the first msb in hash1
// 0000x   : 5
// 000x    : 4
// 00x     : 3
// 0x      : 2
// default : 1
// zeros should be up to 31 (not 32) to save space in hist tables
table mtel_ucounter_set_zeros {
    reads {
        ucounter_md.hash_1 : ternary;
    }
    actions {
        ucounter_set_zeros;
    }
    size : 33;
}

register ucounter_reg {
    width          : 64; 
    instance_count : REGISTER_INSTANCES;
}

blackbox stateful_alu mtel_ucounter_alu {
    reg: mtel_ucounter_reg;
    condition_lo: register_lo < ucounter_md.zeros;
    condition_hi: register_hi != mtel_md.epoch; 
    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: ucounter_md.zeros;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    update_hi_1_value: mtel_md.epoch;

// old_zeros = 0 if epoch changed
    output_predicate: not condition_hi;
    output_value: register_lo;
    output_dst: ucounter_md.old_zeros;
}

action ucounter_update_salu() {
    mtel_ucounter_alu.execute_stateful_alu(ucounter_md.hash_2_m1);
}

table mtel_ucounter_update {
    actions { ucounter_update_salu; }
}

register ucounter_hist1_reg {
    width          : 64; 
    instance_count : UCOUNTER_HIST_SIZE;
}

blackbox stateful_alu mtel_ucounter_hist1_salu {
    reg: mtel_ucounter_hist1_reg;

    condition_hi: register_hi == mtel_md.epoch;
    update_lo_2_predicate: condition_hi;
    update_lo_2_value: register_lo + 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: 1;

    update_hi_1_value: mtel_md.epoch;
}

register ucounter_hist2_reg {
    width          : 64; 
    instance_count : UCOUNTER_HIST_SIZE;
}

blackbox stateful_alu mtel_ucounter_hist2_salu {
    reg: mtel_ucounter_hist2_reg;

    condition_hi: register_hi == mtel_md.epoch;
    update_lo_2_predicate: condition_hi;
    update_lo_2_value: register_lo + 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: 1;

    update_hi_1_value: mtel_md.epoch;
}

field_list ucounter_hist1_full_index {
    mtel_md.index;
    ucounter_md.zeros;
}

field_list ucounter_hist2_full_index {
    mtel_md.index;
    ucounter_md.old_zeros;
}

field_list_calculation ucounter_hist1_full_index_calc {
    input {
        ucounter_hist1_full_index;
    }
    algorithm : identity_lsb;
    output_width : UCOUNTER_HIST_SIZE_LOG;
}

field_list_calculation ucounter_hist2_full_index_calc {
    input {
        ucounter_hist2_full_index;
    }
    algorithm : identity_lsb;
    output_width : UCOUNTER_HIST_SIZE_LOG;
}

action ucounter_hist1_salu_execute() {
    mtel_ucounter_hist1_salu.execute_stateful_alu_from_hash(ucounter_hist1_full_index_calc);
    modify_field(ucounter_md.update_hist, 1);
}

@pragma ways 2
table mtel_ucounter_hist1_update {
    reads {
        ucounter_md.old_zeros : exact;
        ucounter_md.zeros     : exact;
    }
    actions {
        ucounter_hist1_salu_execute;
    }
    size: 497; // [0-31] * [1-31]/2 + 1 = 32*31/2 + 1 
}

action ucounter_hist2_salu_execute() {
    mtel_ucounter_hist2_salu.execute_stateful_alu_from_hash(ucounter_hist2_full_index_calc);
}

table mtel_ucounter_hist2_update {
    actions {ucounter_hist2_salu_execute;}
    default_action:ucounter_hist2_salu_execute;
    size:1;
}

