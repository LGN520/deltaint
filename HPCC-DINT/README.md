# HPCC-PINT simulation

Please see [PINT_README.d](./PINT_README.md) for original readme of HPCC-DINT.

## How to run

- Perform once: `bash gen_traffic_files.sh`
- `bash build.sh`
- `bash run_hpcc_fb.sh; bash run_hpcc_pint1_fb.sh; bash run_hpcc_dint1_fb.sh >tmp.out 2>&1` for facebook dataset
- `bash run_hpcc_wb.sh; bash run_hpcc_pint1_wb.sh; bash run_hpcc_dint1_wb.sh >tmp.out 2>&1` for websearch dataset
- `python3 plothelper.py XXX.out` to get INT packet number
- `cd analysis; bash plotDINTVsPINT.sh`
	+ NOTE: the flow size is the number of bytes in original packet (w/o INT header), instead of the number of packets
- `python3 accuracy_analysis XXX.out` to get ARE of all states
	+ Note that we append accuracy.out, so you should delete or move accuracy.out before each time your run the experiment

## NOTE

- To generate trace file for latency quantitle simulation, you must launch run.py with `--enable_tr 1`
	+ Then, run `cd anaylysis; ./trace_reader trace_file` to get trace file

## Changes for DE-DeltaINT

- Change network/utils/int-header.h, network/utils/int-header.cc, point-to-point/model/switch-node.cc, point-to-point/model/rdma-hw.cc
	+ Add zero_hopnum to calculate average bit cost for De-DeltaINT (compare total_hopnum, save_hopnum, and zero_hopnum)
	+ Add pint_power and dint_power for measurement accuracy (compare total_pktnum and truth_collect_cnt)
- Settings (is\_dint in simulation/src/point-to-point/model/switch-node.cc; is_dinto/is\_dinte in simulation/src/point-to-point/model/rdma-hw.cc)
	+ For PINT: set is\_dint, is\_dinto, and is\_dinte as false
	+ For DeltaINT-O: set is\_dint and is\_dinto as true, and is\_dinte as false
	+ For DeltaINT-E: set is\_dint and is\_dinte as true, and is\_dinto as false
- To get fraction of recirculated packets, uncomment dint_nlarger and dint_nsmaller in simulation/src/network/utils/int-header.\*
	+ `python3 plothelper_recirfrac.py XXX.out` to get recirculation fraction
