# [DeltaINT](http://adslab.cse.cuhk.edu.hk/software/deltaint)

---

## Paper

**Siyuan Sheng, Qun Huang, Patrick P. C. Lee.**
DeltaINT: Toward General In-band Network Telemetry with Extremely Low Bandwidth Overhead.
*ICNP, 2021.*

---

## Content

- DeltaINT-O
	+ DeltaINT with delta omission
- DeltaINT-E
	+ DeltaINT with delta encoding
- In DeltaINT-O/E
	+ Software experiments
		* HPCC-DINT
			- Source code of congestion control
		* INTPath-DINT
			- Source code of gray failure detection
		* Mininet-DINT
			- Source code of path tracing, latency measurement, and fine-grained monitoring
	+ Hardware experiment
	+ NOTE: as the only difference between DeltaINT-O and DeltaINT-E is on metadata insert for negligible delta (i.e., omission or encoding), while all other operations are the same (e.g., state load, delta calculation, and state update), we dump per-node device-internal states and calculates the bandwidth cost of DeltaINT-E by software simulation in software experiments

## How to run

Please see README.md in each directory.


