# HPCC-PINT simulation

Please see [PINT_README.d](./PINT_README.md) for original readme of HPCC-DINT.

## How to run

- `bash build.sh`
- `bash run_hpcc_fb.sh; bash run_hpcc_pint1_fb.sh; bash run_hpcc_dint1_fb.sh >tmp.out 2>&1` for facebook dataset
- `bash run_hpcc_wb.sh; bash run_hpcc_pint1_wb.sh; bash run_hpcc_dint1_wb.sh >tmp.out 2>&1` for websearch dataset
- `cd analysis; bash plotDINTVsPINT.sh`

## NOTE

- To generate trace file for latency quantitle simulation, you must launch run.py with `--enable_tr 1`
