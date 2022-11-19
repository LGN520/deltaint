sudo ovs-vsctl del-br s999

for ((i=0;i<6;i++))
do
	for ((j=0;j<6;j++))
	do
		tmpifname="s${i}-eth${j}"
		sudo ifconfig ${tmpifname} down
	done
done

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

