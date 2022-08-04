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

#define DROP_REGISTER_WIDTH 64
#define DROP_REGISTER_LENGTH MTEL_NUM_SUMMARIES 

register mtel_drop_reg {
    width : DROP_REGISTER_WIDTH;
    instance_count : DROP_REGISTER_LENGTH;
    attributes : saturating;
}

blackbox stateful_alu mtel_drop_reg_write_salu {
    reg: mtel_drop_reg;

    condition_hi: register_hi == mtel_md.epoch;
    update_lo_2_predicate: condition_hi;
    update_lo_2_value: register_lo + 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: 1;

    update_hi_1_value: mtel_md.epoch;
}

action drop_reg_write_salu_execute() {
    mtel_drop_reg_write_salu.execute_stateful_alu(mtel_md.index);
    drop();
}

blackbox stateful_alu mtel_drop_reg_read_salu {
    reg: mtel_drop_reg;

    condition_hi: register_hi == mtel_md.epoch;

    output_predicate: condition_hi;
    output_value: register_lo;
    output_dst: mtel_least_int.read_value;
}

action drop_reg_read_salu_execute() {
    mtel_drop_reg_read_salu.execute_stateful_alu(mtel_md.index);
}

table mtel_drop_reg_update {
    reads {
        mtel_least_int.valid: exact;
    }
    actions {
        drop_reg_read_salu_execute;
        drop_reg_write_salu_execute;
    }
    size: 3;
}
