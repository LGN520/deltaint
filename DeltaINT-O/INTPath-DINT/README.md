# INT-Path based on DeltaINT

Please see [INTPATH_README.md](./INTPATH_README.md) for original readme of INT-Path.

## NOTES

- Do not set all zero in host field of IP address of interface!
- Use Redis for failure detection instead of mysql
- Install controller (Mininet does not provide built-in controller though it provides built-in OVS)
	+ Use `sudo apt-get install openvswitch-testcontroller`, `sudo ln /usr/bin/ovs-testcontroller /usr/bin/controller`, `sudo service openvswitch-testcontroller stop`, and `sudo update-rc.d openvswitch-testcontroller disable` to install OVS controller for mininet
	+ Or, use `sudo pip3 install ryu` to install ryu controller for mininet
- If python > 3.7 (e.g., 3.9), to support bmv2 (and thrift)
	+ Change "from ttypes" as "from \.ttypes" in /home/ssy/behavioral-model-main/tools/bm_runtime/\*.py
	+ Change "except XXX, ouch:" as "except XXX as ouch:" in /home/ssy/behavioral-model-main/tools/bm_runtime/\*.py
	+ Add "isinstance(str_val, str)" before "bytes(str_val, "utf-8")" in /home/ssy/.local/lib/python3.9/site-packages/thrift/compat.py
	+ Change "xrange" as "range" in /home/ssy/behavioral-model-main/tools/bm_runtime/standard/Standard.py 

## How to run

- Preliminaries
	+ Ryu controller, python 3.6, p4c, bmv2 (including thrift and nanomsg), and mininet
	+ Install redis, enable unix socket (set path as /var/run/redis/redis.sock, set unix perm as 777, and set notify-keyspace-events KEA to enable key-expire-notification) in /etc/redis/redis.conf 
- Launch OVS and redis
	+ `ovs-ctl start`
		* Use `ovs-ctl stop` to stop
		* NOTE: add /usr/share/openvswitch/scripts/ into PATH for ovs-ctl
	+ `/etc/init.d/redis-server start`
		* Use `/etc/init.d/redis-server stop` to stop
- Path change
	+ Change `sys.path`, `bmv2_path`, and `switch_path` in controller/app.py accordingly
	+ Change `ryu path` in controller/topoMaker.py accordingly
- Compile p4 code
	+ `cd p4app; bash run.sh`
- Clean tmp directory
	+ `sudo rm -r packet/tmp`
- Generate topology
	+ For single leaf layer, use `cd conroller; python3 topo_generate.py k`, where k is the scale of network like 2
	+ For multiple leaf layers, use `cd conroller; python3 topo_generate_multilayer.py k`, where k is the number of leaf layers like 2
- Run (must clean tmp directory before running and evaluating)
	+ Set is_detect = 0 in config.json
	+ `cd controller; sudo python3 app.py`
	+ `cd controller; sudo python3 BW_evaluate.py`
	+ Set is_detect = 1, and is_linkdown = 0 or 1 in config.json (0: heavy latency; 1: link failure)
	+ `cd controller; sudo python3 app.py`
	+ See detector.log for detection time
		* NOTE: link failure or heavy latency detection is irrelevant with negligible delta
	+ NOTE for INT-Path
		* For gray failure detection time, as it is runtime statistics, use method = INT-Path in config.json
		* For BW cost, as INT-Path BW is constantly determined by path length, we do not dump BW.txt for INT-Path individually; instead, we calculate both the BW cost of INT-Path and DeltaINT simultaneously (i.e., use method = DeltaINT in config.json)

## NOTEs

- For errno 113 when connecting localhost to mininet.host, check ryu-manager.log to see if ryu controller is launched correctly
	+ Reason: OVS can direclty see interface of localhost, but need controller to see interface of mininet.host
	+ For msgpack, run `pip3 install msgpack-python` and rename msgpack_python as msgpack in site-packages
	+ For eventlet, run `pip3 install eventlet==0.30.2` to install older version
- For errno 111 when connecting localhost to mininet.host, set is_debug = 1 in config.json, and see log files in packet/tmp
	+ Reason: sendint.py is not launched correctly
	+ `pip3 install bitstring; pip3 install redis; pip3 install scapy`
- Clear environment when being interrupted by errors
	+ `sudo mn -c`
	+ `sudo bash clear.sh`
- Ignore error msg of "could not open network device (no such device)" for `ovs-vsctl show`
