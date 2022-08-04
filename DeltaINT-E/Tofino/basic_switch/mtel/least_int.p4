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

action least_int_finish_run(){
    modify_field(mtel_md.set_index, 1);
}

table mtel_least_int_finish {
    actions{least_int_finish_run;}
    default_action:least_int_finish_run;
    size:1;
}

// index is passed as action_param to make sure
// we set start_index as first subsummary to later check if search finished
// bringing data from action param vs bringing mask gives more freedom for phvs
action least_int_start_run(index, index_1){
    modify_field(ethernet.etherType, ETHERTYPE_MTEL_RECIRC);
    add_header(mtel_least_int);
    modify_field(mtel_least_int.index, index);
    modify_field(mtel_least_int.value, 0x7FFFFFFF);
    modify_field(mtel_least_int.prev_value, 0);
    modify_field(mtel_least_int.start_index, index);
    modify_field(mtel_least_int.old_index, index);
    modify_field(mtel_least_int.next_index, index_1);
}

@pragma dynamic_table_key_masks 1
table mtel_least_int_start {
    reads{
        mtel_md.index : exact;
    }
    actions {
        least_int_start_run;
    }
    size: MTEL_LEAST_INT_START_TABLE_SIZE; 
}

action least_int_add_run(){
    add_to_field(mtel_least_int.prev_value, mtel_least_int.read_value); 
}

table mtel_least_int_add {
    actions{least_int_add_run;}
    default_action:least_int_add_run;
    size:1;
}

action least_int_sub_run(){
    // piggyback subtraction from last run of loop
    subtract(mtel_least_int.prev_value, mtel_least_int.value, mtel_least_int.prev_value);
}

// mtel_least_int.valid and next_index=1st in sub summary in pktgen pipe --> subtract
@pragma dynamic_table_key_masks 1
table mtel_least_int_sub{
    reads {
        mtel_least_int.next_index     : exact;
    }
    actions{
        least_int_sub_run;
    }
    size: 2; 
}

