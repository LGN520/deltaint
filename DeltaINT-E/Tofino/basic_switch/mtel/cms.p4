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
#define REGISTER_WIDTH 64
#define VALUE_WIDTH 32  // REGISTER_WIDTH/2
#define REGISTER_LENGTH 32768
#define REGISTER_LENGTH_LOG 15 //log(REGISTER_LENGTH)

header_type cms_md_t {
    fields {
        v1 : VALUE_WIDTH;
        v2 : VALUE_WIDTH;
        v3 : VALUE_WIDTH;
        v4 : VALUE_WIDTH;
        diff1: VALUE_WIDTH;
        diff2: VALUE_WIDTH;
        diff3: VALUE_WIDTH;
        totalLen32: 32;
    }
}

metadata cms_md_t cms_md;

// cms_1 will use switch.p4 hash crc_16

field_list_calculation cms_hash_2 {
    input {lkp_ipv4_hash1_fields;}
    algorithm : crc_32c;
    output_width : REGISTER_LENGTH_LOG;
}

field_list_calculation cms_hash_3 {
    input {lkp_ipv4_hash1_fields;}
    algorithm : crc_32d;
    output_width : REGISTER_LENGTH_LOG;
}

field_list_calculation cms_v6_hash_2 {
    input {lkp_ipv6_hash1_fields;}
    algorithm : crc_32c;
    output_width : REGISTER_LENGTH_LOG;
}

field_list_calculation cms_v6_hash_3 {
    input {lkp_ipv6_hash1_fields;}
    algorithm : crc_32d;
    output_width : REGISTER_LENGTH_LOG;
}

register mtel_cms_hashtable_1 {
    width : REGISTER_WIDTH;
    instance_count : REGISTER_LENGTH;
    attributes : saturating;
}

register mtel_cms_hashtable_2 {
    width : REGISTER_WIDTH;
    instance_count : REGISTER_LENGTH;
    attributes : saturating;
}

register mtel_cms_hashtable_3 {
    width : REGISTER_WIDTH;
    instance_count : REGISTER_LENGTH;
    attributes : saturating;
}

register mtel_cms_hashtable_4 {
    width : REGISTER_WIDTH;
    instance_count : REGISTER_LENGTH;
    attributes : saturating;
}

blackbox stateful_alu mtel_cms_update_hashtable_1_salu {
    reg: mtel_cms_hashtable_1;

    condition_lo: mtel_md.epoch == register_hi;
    
    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + pktsize_md.len;
    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: pktsize_md.len;

    update_hi_1_value: mtel_md.epoch;

    output_value: alu_lo;
    output_dst: cms_md.v1;
}

blackbox stateful_alu mtel_cms_update_hashtable_2_salu {
    reg: mtel_cms_hashtable_2;

    condition_lo: mtel_md.epoch == register_hi;
    
    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + pktsize_md.len;
    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: pktsize_md.len;

    update_hi_1_value: mtel_md.epoch;

    output_value: alu_lo;
    output_dst: cms_md.v2;
}

blackbox stateful_alu mtel_cms_update_hashtable_3_salu {
    reg: mtel_cms_hashtable_3;

    condition_lo: mtel_md.epoch == register_hi;
    
    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + pktsize_md.len;
    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: pktsize_md.len;

    update_hi_1_value: mtel_md.epoch;

    output_value: alu_lo;
    output_dst: cms_md.v3;
}

blackbox stateful_alu mtel_cms_update_hashtable_4_salu {
    reg: mtel_cms_hashtable_4;

    condition_lo: mtel_md.epoch == register_hi;
    
    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + pktsize_md.len;
    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: pktsize_md.len;

    update_hi_1_value: mtel_md.epoch;

    output_value: alu_lo;
    output_dst: cms_md.v4;
}

action cms_update_hashtable_1() {
    mtel_cms_update_hashtable_1_salu.execute_stateful_alu(hash_metadata.hash1);
}

action cms_update_hashtable_2() {
    mtel_cms_update_hashtable_2_salu.execute_stateful_alu_from_hash(cms_hash_2);
}

action cms_update_hashtable_3() {
    mtel_cms_update_hashtable_3_salu.execute_stateful_alu_from_hash(cms_hash_3);
}

action cms_update_hashtable_4() {
    mtel_cms_update_hashtable_4_salu.execute_stateful_alu(mtel_md.flowhash);
    subtract(cms_md.diff1, cms_md.v2, cms_md.v1);
}

@pragma stage 3
table mtel_cms_update_hashtable_1 {
    actions {cms_update_hashtable_1;}
    default_action: cms_update_hashtable_1;
    size:1;
}

@pragma stage 3
table mtel_cms_update_hashtable_2 {
    actions {cms_update_hashtable_2;}
    default_action: cms_update_hashtable_2;
    size:1;
}

@pragma stage 7
table mtel_cms_update_hashtable_3 {
    actions {cms_update_hashtable_3;}
    default_action: cms_update_hashtable_3;
    size:1;
}

@pragma stage 7
table mtel_cms_update_hashtable_4 {
    actions {cms_update_hashtable_4;}
    default_action: cms_update_hashtable_4;
    size:1;
}

action cms_v6_update_hashtable_2() {
    mtel_cms_update_hashtable_2_salu.execute_stateful_alu_from_hash(cms_v6_hash_2);
}

action cms_v6_update_hashtable_3() {
    mtel_cms_update_hashtable_3_salu.execute_stateful_alu_from_hash(cms_v6_hash_3);
}

@pragma stage 3
table mtel_cms_v6_update_hashtable_2 {
    actions {cms_v6_update_hashtable_2;}
    default_action:cms_v6_update_hashtable_2;
    size:1;
}

@pragma stage 7
table mtel_cms_v6_update_hashtable_3 {
    actions {cms_v6_update_hashtable_3;}
    default_action:cms_v6_update_hashtable_3;
    size:1;
}

field_list cms_totalLen_hash_fields {
    pktsize_md.len;
}

field_list_calculation cms_totalLen32 {
    input {cms_totalLen_hash_fields;}
    algorithm : identity_lsb;
    output_width : 32;
}

// if diff1<0 then 2<1 so copy 2 to 1
action cms_subtract_v2() {
    subtract(cms_md.diff1, cms_md.v3, cms_md.v2);
    subtract(cms_md.diff2, cms_md.v4, cms_md.v2);
    subtract(cms_md.diff3, cms_md.v4, cms_md.v3);
    modify_field(cms_md.v1, cms_md.v2);
    modify_field_with_hash_based_offset(cms_md.totalLen32, 0, cms_totalLen32, 4294967296);
}

action cms_subtract_v1() {
    subtract(cms_md.diff1, cms_md.v3, cms_md.v1);
    subtract(cms_md.diff2, cms_md.v4, cms_md.v1);
    subtract(cms_md.diff3, cms_md.v4, cms_md.v3);
    modify_field_with_hash_based_offset(cms_md.totalLen32, 0, cms_totalLen32, 4294967296);
}

table mtel_cms_subtract {
    reads {
        cms_md.diff1 mask 0x80000000: exact;
    }
    actions {
        cms_subtract_v1;
        cms_subtract_v2;
    }
    size : 3;
}

action cms_copy_min_from_1() {
    subtract(cms_md.v2, cms_md.v1, cms_md.totalLen32);
}

action cms_copy_min_from_3() {
    modify_field(cms_md.v1, cms_md.v3);
    subtract(cms_md.v2, cms_md.v3, cms_md.totalLen32);
}

action cms_copy_min_from_4() {
    modify_field(cms_md.v1, cms_md.v4);
    subtract(cms_md.v2, cms_md.v4, cms_md.totalLen32);
}

// diff1, diff2, diff3
// -    , -    , -     : 4
// -    , -    , +     : 3
// -    , +    , -     : invalid
// -    , +    , +     : 3
// +    , -    , -     : 4
// +    , -    , +     : invalid
// +    , +    , -     : 1
// +    , +    , +     : 1
table mtel_cms_find_min {
    reads {
        cms_md.diff1 mask 0x80000000 : exact;
        cms_md.diff2 mask 0x80000000 : exact;
        cms_md.diff3 mask 0x80000000 : exact;
    }
    actions {
        cms_copy_min_from_1;
        cms_copy_min_from_4; 
        cms_copy_min_from_3; 
    }
    size : 8;
}

