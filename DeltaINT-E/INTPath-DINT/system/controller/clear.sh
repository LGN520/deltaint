sudo ovs-vsctl del-br s999

sudo ifconfig s0-eth1 down
sudo ifconfig s0-eth2 down
sudo ifconfig s1-eth1 down
sudo ifconfig s1-eth2 down
sudo ifconfig s1-eth3 down
sudo ifconfig s2-eth1 down
sudo ifconfig s2-eth2 down
sudo ifconfig s2-eth3 down
sudo ifconfig s2-eth4 down
sudo ifconfig s3-eth1 down
sudo ifconfig s3-eth2 down
sudo ifconfig s3-eth3 down
sudo ifconfig s3-eth4 down
sudo ifconfig s4-eth1 down
sudo ifconfig s4-eth2 down
sudo ifconfig s4-eth3 down
sudo ifconfig s5-eth1 down
sudo ifconfig s5-eth2 down

sudo ifconfig h-ens38 down
sudo ifconfig s-ens38 down
#sudo ifconfig ens38 down

#service openvswitch stop
rm -rf /etc/openvswitch/conf.db
#service openvswitch start

pids=($(sudo ps -aux | grep ryu | awk '{print $2}'))
for i in $(seq 0 $[${#pids[*]}-1])
do
	sudo kill -9 ${pids[i]}
done

pids=($(sudo ps -aux | grep detector | awk '{print $2}'))
for i in $(seq 0 $[${#pids[*]}-1])
do
	sudo kill -9 ${pids[i]}
done

