field_list_calculation ingress_tstamp_hi_32_hash_fields_calc {
    input { ingress_tstamp_hi_hash_fields; }
    algorithm : identity_msb;
    output_width : 32;
}

#ifdef MTEL_TEST
// for testing we can inject epoch numbers
action epoch_set(monitor, hh_bin, e){
    modify_field(mtel_md.epoch, e);
#else
action epoch_set(monitor, hh_bin){
    modify_field_with_hash_based_offset(mtel_md.epoch, 0,
      ingress_tstamp_hi_32_hash_fields_calc, 4294967296);
#endif // MTEL_TEST
    modify_field(mtel_md.monitor, monitor);
    modify_field(fsd_md.reg2_bin_index, hh_bin);
}

#ifdef MTEL_TEST
action epoch_set_and_advance(monitor, hh_bin, e){
    epoch_set(monitor, hh_bin, e);
#else
action epoch_set_and_advance(monitor, hh_bin){
    epoch_set(monitor, hh_bin);
#endif // MTEL_TEST
 
  // write original value of prev_value on mtel_least_int.value
  // prev_value became value - prev_value in least_int_sub
  // if prev_value>0 --> value = value-(value-prev_value) = prev_value 
  subtract(mtel_least_int.value, mtel_least_int.value, mtel_least_int.prev_value);
  // use old_index instead of next_index - 1 for phv issue
  modify_field(mtel_least_int.index, mtel_least_int.old_index);
}

// tstamp     , port          , valid, prev_value, index
// x          , recirc1stpipe , 1    , +         , 1stsub : epoch_set_and_advance(monitored=0)
// x          , x             , x    , x         , x      : epoch_set(monitored=0): disable
// in interval, monitored     , x    , x         , x      : epoch_set (monitored=1)
// default                                                : epoch_set (monitored=0)
table mtel_epoch {
    reads {
        ig_intr_md.ingress_mac_tstamp : ternary;
        ig_intr_md.ingress_port       : ternary;
        mtel_least_int.valid          : ternary;
        mtel_least_int.prev_value     : ternary; // only the top bit
        mtel_least_int.next_index     : ternary;
    }
    actions {
        epoch_set;
        epoch_set_and_advance;
    }
    size: 70; // > # ingress ports per pipe + 4
}

register mtel_index_reg {
    width          : 64; // >= 2*MTEL_NUM_SUMMARIES_LOG
    instance_count : 2; 
}

// set high bit to know which index is used for current
// at control plane
blackbox stateful_alu mtel_index_get_alu {
    reg: mtel_index_reg;
    condition_lo: register_hi == 1; // to force hi and low
    update_hi_1_value: mtel_md.epoch;
    output_value: register_lo;
    output_dst: mtel_md.index;
}

blackbox stateful_alu mtel_index_set_alu {
    reg: mtel_index_reg;
    update_lo_1_value: mtel_least_int.index;
    update_hi_1_value: mtel_md.epoch;
}

action get_index(odd_even_index){
  mtel_index_get_alu.execute_stateful_alu(odd_even_index);
}

action set_index(odd_even_index){
  mtel_index_set_alu.execute_stateful_alu(odd_even_index);
}

action next_sindex(){
  // which index to read for this pass
  modify_field(mtel_md.index, mtel_least_int.next_index);
  modify_field(mtel_least_int.old_index, mtel_least_int.next_index);
}

action next_summary(){
  next_sindex();
  
  // reset accumulated value
  modify_field(mtel_least_int.prev_value, 0);
}

action epoch_mask_run(odd_even_index, m){
   get_index(odd_even_index);
   bit_and(mtel_md.epoch, mtel_md.epoch, m);
}

// setindex, valid, epoch, index           :
// 0       , 0    , oddx , x               : getindex(1)
// 0       , 0    , evenx, x               : getindex(0)
// 1       , 1    , oddx , x               : setindex(0)
// 1       , 1    , evenx, x               : setindex(1)
// 0       , 1    , x    , 1st_sub         : next_summary() on first pipe
// 0       , 1    , x    , x               : next_sindex() // let it accumulate
// table can be exact match for power using dynhash but will use hash bits and push tables
table mtel_epoch_mask{
    reads {
        mtel_md.set_index         : exact;
        mtel_least_int.valid      : exact;
        mtel_md.epoch             : ternary; // only the bit that says epoch is odd/even
        mtel_least_int.next_index : ternary; 
    }
    actions{
        epoch_mask_run;
        next_sindex;
        next_summary;
        set_index;
    }
    size: 10; 
}

register mtel_epoch_reg {
    width          : 32;
    instance_count : MTEL_NUM_SUMMARIES;
}

blackbox stateful_alu mtel_epoch_save_alu {
    reg: mtel_epoch_reg;
    condition_lo: register_lo != mtel_md.epoch; 
    update_lo_1_value: mtel_md.epoch;
}

field_list_calculation cms_v6_hash_4 {
    input {lkp_ipv6_hash1_fields;}
    algorithm : crc_32q;
    output_width : REGISTER_LENGTH_LOG;
}

field_list_calculation cms_hash_4 {
    input {lkp_ipv4_hash1_fields;}
    algorithm : crc_32q;
    output_width : REGISTER_LENGTH_LOG;
}

action epoch_save_run(index){
    mtel_epoch_save_alu.execute_stateful_alu(index);
}

action mtel_hash_prepare(){
    modify_field(pktsize_md.len, ipv4.totalLen);
    modify_field_with_hash_based_offset(mtel_md.flowhash, 0,
      cms_hash_4, 65536);
}
action mtel_hash_prepare_v6(){
    add(pktsize_md.len, ipv6.payloadLen, 40);
    modify_field_with_hash_based_offset(mtel_md.flowhash, 0,
      cms_v6_hash_4, 65536);
}

action mtel_hash_miss(){
    modify_field(mtel_md.monitor, 0); // only monitor v4, v6
}

// this is to prepare some hash to use crossbar in this stage vs. later stages
table mtel_hash_prepare{
    reads{
        ipv4.valid: exact;
        ipv6.valid: exact;
    }
    actions{
        mtel_hash_prepare;
        mtel_hash_prepare_v6;
        mtel_hash_miss;
    }
    size:4;
}

// The first pktgen packet should keep this updated per index in pipe 0
table mtel_epoch_save{
    reads {
        mtel_md.index : exact;
    }
    actions {
        epoch_save_run;
        nop;
    }
    size: MTEL_NUM_SUMMARIES_1;
}

blackbox stateful_alu mtel_epoch_load_alu {
    reg: mtel_epoch_reg;
    output_value: register_lo;
    output_dst: mtel_md.epoch;
}

action epoch_load_for_least_int(index){
    mtel_epoch_load_alu.execute_stateful_alu(index);
}

table mtel_epoch_load{
    reads {
        mtel_md.index  : exact;
    }
    actions {
        epoch_load_for_least_int;
        nop;
    }
    size: MTEL_NUM_SUMMARIES_1;
}

