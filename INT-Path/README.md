# INT-Path based on DeltaINT

Please see [INTPATH_README.md](./INTPATH_README.md) for original readme of INT-Path.

## NOTES

- Do not set all zero in host field of IP address of interface!
- Use Redis for failure detection instead of mysql
- Install controller (Mininet does not provide built-in controller though it provides built-in OVS)
	+ Use `sudo apt-get install openvswitch-testcontroller`, `sudo ln /usr/bin/ovs-testcontroller /usr/bin/controller`, `sudo service openvswitch-testcontroller stop`, and `sudo update-rc.d openvswitch-testcontroller disable` to install OVS controller for mininet
	+ Or, use `sudo pip3 install ryu` to install ryu controller for mininet

## How to run

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
- Measurement accuracy
	+ Set is_dump as 1 in config.json
	+ `cd controller; sudo python3 app.py`
	+ `cd controller; sudo python3 measurement_accuracy.py`
