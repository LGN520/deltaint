# DINT on Mininet

## Path tracing

- `python3 topo_allocator.py 5`
- `sudo python3 -m p4utils.p4run --config p4app.json`
- `sudo python3 exp.py 5`
- `sudo python3 generate_results.py 5`
- `sudo python3 generate_results_avgbit.py 5`
- `sudo python3 plothelper.py final_results/5/tail/PINT8`

## Latency measurement

- `cd ../HPCC-DINT/analysis; ./trace_reader wb.tr >wb_trace.out 2>&1 &`
	+ You'd better run it in screen if the trace file xxx.tr is large
- `sudo python3 generate_delay_data.py ../HPCC-DINT/analysis/wb_trace.out wb_processed_data`
- `sudo python3 generate_delay_results.py wb_processed_data`

## Fine-grained monitoring

- `cd ../HPCC-DINT/analysis; ./trace_reader wb.tr >wb_trace.out 2>&1 &`
	+ You'd better run it in screen if the trace file xxx.tr is large
- `sudo python3 generate_delay_data.py ../HPCC-DINT/analysis/wb_trace.out wb_processed_data`
- `sudo python3 generate_monitoring_results.py wb_processed_data`

