# INT-Path based on DeltaINT

Please see [INTPATH_README.md](./INTPATH_README.md) for original readme of INT-Path.

## NOTES

- Do not set all zero in host field of IP address of interface!
- Use Redis for failure detection instead of mysql
- Install controller (Mininet does not provide built-in controller though it provides built-in OVS)
	+ Use `sudo apt-get install openvswitch-testcontroller`, `sudo ln /usr/bin/ovs-testcontroller /usr/bin/controller`, `sudo service openvswitch-testcontroller stop`, and `sudo update-rc.d openvswitch-testcontroller disable` to install OVS controller for mininet
	+ Or, use `sudo pip3 install ryu` to install ryu controller for mininet
- If python > 3.6 (e.g., 3.9), to support bmv2 (and thrift)
	+ Change "from ttypes" as "from \.ttypes" in /home/ssy/behavioral-model-main/tools/bm_runtime/\*.py
	+ Change "except XXX, ouch:" as "except XXX as ouch:" in /home/ssy/behavioral-model-main/tools/bm_runtime/\*.py
	+ Add "isinstance(str_val, str)" before "bytes(str_val, "utf-8")" in /home/ssy/.local/lib/python3.9/site-packages/thrift/compat.py
	+ Change "xrange" as "range" in /home/ssy/behavioral-model-main/tools/bm_runtime/standard/Standard.py 

## How to run

- Preliminaries
	+ Ryu controller, python 3.6, p4c, bmv2 (including thrift and nanomsg), and mininet
	+ Install redis, enable unix socket (set path as /var/run/redis/redis.sock, set unix perm as 777, and set notify-keyspace-events KEA to enable key-expire-notification) in /etc/redis/redis.conf 
- Compile p4 code
	+ `cd p4app; bash run.sh`
- Clean tmp directory
	+ `sudo rm -r packet/tmp`
- Generate topology
	+ `cd conroller; python3 topo_generate k`, where k is the scale of network like 3
- Run
	+ `cd controller; sudo python3 app.py`
- Evaluate bandwidth (must clean tmp directory before running and evaluating)
	+ `cd controller; bash BW_evaluate.sh`
- See detector.log for detection time
- Measurement accuracy
	+ Set is_dump as 1 in config.json
	+ `cd controller; sudo python3 app.py`
	+ `cd controller; sudo python3 measurement_accuracy.py`
	+ NOTE: it dumps complete INT statistics in packet/tmp/ by INT-Path for a given epoch length, and simulate DE-DeltaINT in software to get bandwidth usage and measurement accuracy
