# HPCC-PINT simulation

Please see [PINT_README.d](./PINT_README.md) for original readme of HPCC-DINT.

## How to run

- Run only once: `bash gen_traffic_files.sh`
- Update switch-node.cc and rdma-hw.cc as mentioned in NOTE, and run `bash build.sh`
- Based on the chosen in-band network telemetry technique and workload, run one of the following commands
	- `bash run_hpcc_pint1_fb.sh; bash run_hpcc_dint1_fb.sh >tmp.out 2>&1` for PINT/DeltaINT-E on facebook dataset
	- `bash run_hpcc_pint1_wb.sh; bash run_hpcc_dint1_wb.sh >tmp.out 2>&1` for PINT/DeltaINT-E on websearch dataset
- `python3 plothelper.py tmp.out` to get average bit cost 
- `cd analysis; bash plotDINTVsPINT.sh`
	+ NOTE: the flow size is the number of bytes in original packet (w/o INT header), instead of the number of packets

<!-- - `python3 accuracy_analysis.py accuracy.out` to get ARE of all states
	+ Note that we append accuracy.out, so you should delete or move accuracy.out before each time your run the experiment -->

## NOTE

- To generate trace file for latency quantitle simulation, you must launch run.py with `--enable_tr 1`
	+ Then, run `cd anaylysis; ./trace_reader trace_file` to get trace file
- In switch-node.cc and rdma-hw.cc
	+ For PINT: set is\_dint and is\_dinte as false
	+ For DeltaINT-E: set is\_dint and is\_dinte as true
	+ NOTE: we fix is\_dinto as false in this repo

