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
// Flow size distribution

#define FSD_BIN_COUNT 16
#define FSD_BIN_COUNT_WIDTH 4  // log(FSD_BIN_COUNT)
#define FSD_REGISTER_WIDTH 64
#define FSD_REGISTER_LENGTH_LOG 14  // FSD_BIN_COUNT_WIDTH + MTEL_NUM_SUMMARIES_LOG
#define FSD_REGISTER_LENGTH 16384  // 2**FSD_REGISTER_LENGTH_LOG

header_type fsd_md_t {
    fields {
        reg1_bin_index : FSD_BIN_COUNT_WIDTH;
        reg2_bin_index : FSD_BIN_COUNT_WIDTH;
    }
}

metadata fsd_md_t fsd_md;

action fsd_reg1_index_set(index) {
    modify_field(fsd_md.reg1_bin_index, index);
}

action fsd_reg2_index_set(index) {
    modify_field(fsd_md.reg2_bin_index, index);
}

table mtel_fsd_reg1_index {
    reads {
        cms_md.v1: ternary;
    }
    actions {
        fsd_reg1_index_set;
    }
    size: 512; // will be used as range match > FSD_BIN_COUNT*32/2
}

table mtel_fsd_reg2_index {
    reads {
        cms_md.v2: ternary;
    }
    actions {
        fsd_reg2_index_set;
    }
    size: 512; // will be used as range match > FSD_BIN_COUNT*32/2
}

field_list fsd_reg1_full_index {
    mtel_md.index;
    fsd_md.reg1_bin_index;
}

field_list_calculation fsd_reg1_full_index_calc {
    input {
        fsd_reg1_full_index;
    }
    algorithm : identity_lsb;
    output_width : FSD_REGISTER_LENGTH_LOG;
}

register mtel_fsd_reg1 {
    width : FSD_REGISTER_WIDTH;
    instance_count : FSD_REGISTER_LENGTH;
    attributes : saturating;
}

blackbox stateful_alu mtel_fsd_reg1_salu {
    reg: mtel_fsd_reg1;

    condition_hi: register_hi == mtel_md.epoch;
    update_lo_2_predicate: condition_hi;
    update_lo_2_value: register_lo + 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: 1;

    update_hi_1_value: mtel_md.epoch;
}

action fsd_reg1_salu_execute() {
    mtel_fsd_reg1_salu.execute_stateful_alu_from_hash(fsd_reg1_full_index_calc);
}

table mtel_fsd_reg1_update {
    actions {
        fsd_reg1_salu_execute;
    }
    default_action:fsd_reg1_salu_execute;
    size: 1;
}

field_list fsd_reg2_full_index {
    mtel_md.index;
    fsd_md.reg2_bin_index;
}

field_list_calculation fsd_reg2_full_index_calc {
    input {
        fsd_reg2_full_index;
    }
    algorithm : identity_lsb;
    output_width : FSD_REGISTER_LENGTH_LOG;
}

register mtel_fsd_reg2 {
    width : FSD_REGISTER_WIDTH;
    instance_count : FSD_REGISTER_LENGTH;
    attributes : saturating;
}

blackbox stateful_alu mtel_fsd_reg2_salu {
    reg: mtel_fsd_reg2;

    condition_hi: register_hi == mtel_md.epoch;
    update_lo_2_predicate: condition_hi;
    update_lo_2_value: register_lo + 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: 1;

    update_hi_1_value: mtel_md.epoch;
}

action fsd_reg2_salu_execute() {
    mtel_fsd_reg2_salu.execute_stateful_alu_from_hash(fsd_reg2_full_index_calc);
}

blackbox stateful_alu mtel_fsd_reg2_hh_salu {
    reg: mtel_fsd_reg2;

    condition_hi: register_hi == mtel_md.epoch;

    output_predicate: condition_hi;
    output_value: register_lo;
    output_dst: mtel_least_int.read_value;
}

action fsd_reg2_hh_salu_execute() {
    mtel_fsd_reg2_hh_salu.execute_stateful_alu_from_hash(fsd_reg2_full_index_calc);
}

table mtel_fsd_reg2_update {
    reads {
        mtel_least_int.valid : exact;
    }
    actions {
        fsd_reg2_salu_execute;
        fsd_reg2_hh_salu_execute;
    }
    size: 3;
}

