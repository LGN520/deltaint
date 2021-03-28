# -*- coding:utf-8 -*-

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch, OVSController
from p4_mininet import P4Switch, P4Host

import os
import copy
import time
import subprocess


class MakeSwitchTopo(Topo):
    """
    Mapping the topology in controller to Mininet
    """

    def __init__(self, sw_path, json_path, app_topo, **opts):
        """
        Make Mininet Host, Switch and Link entity

        :param sw_path: switch path (use bmv2's simple_switch target in this case)
        :param json_path: a compiled JSON file from P4 code
        :param app_topo: the Ctrl class instance to get informatin
        """
        Topo.__init__(self, **opts)

        self.switchSum = len(app_topo.switches)
        self.hostSum = len(app_topo.hosts)

        self.mn_switches = []
        self.mn_hosts = []
        for i in range(self.switchSum):
            self.mn_switches.append(self.addSwitch(app_topo.switches[i].name,
                                                   sw_path=sw_path,
                                                   json_path=json_path,
                                                   thrift_port=app_topo.switches[i].thriftPort,
                                                   pcap_dump=False))
        for i in range(self.hostSum):
            if app_topo.hosts[i] != None:
                self.mn_hosts.append(self.addHost(app_topo.hosts[i].name,
                                                  ip=app_topo.hosts[i].ipAddress + "/24",
                                                  mac=app_topo.hosts[i].macAddress))
            else:
                self.mn_hosts.append(None)
        for i in range(self.switchSum):
            for j in range(app_topo.switches[i].portSum):
                deviceNum = int(
                    app_topo.switches[i].ports[j].deviceName[1:])
                if app_topo.switches[i].ports[j].deviceName.startswith('s'):
                    if i < deviceNum:
                        self.addLink(
                            self.mn_switches[i], self.mn_switches[deviceNum])
                else:
                    self.addLink(
                        self.mn_switches[i], self.mn_hosts[deviceNum])


class TopoMaker(object):
    """
    Make topology in Mininet
    """

    def __init__(self, switchPath, jsonPath, topoObj):
        """
        Initial topology maker

        :param sw_path: switch path (use bmv2's simple_switch target in this case)
        :param json_path: a compiled JSON file from P4 code
        :param topoObj: the Ctrl class instance to get informatin
        """
        self.topo = MakeSwitchTopo(switchPath, jsonPath, topoObj)
        self.topoObj = topoObj

    def genMnTopo(self):
        """
        Launch Mininet topology and add some commands (like disable IPv6, open INT sender/packet client/INT parser) to host and switch & start OVS and ryu controller
        """
        setLogLevel('debug')
        self.net = Mininet(topo=self.topo,
                           host=P4Host,
                           switch=P4Switch,
                           controller=None)
        controller_list = []
        # Controler is out of the management of mininet
        # NOTE: If use remote controller, mininet will not run `controller` when start()
        # We must launch the controller before running the script
        #os.system("controller ptcp:6653:127.0.0.1 --log-file=./ovs-testcontroller.log &") # tcp: connection refused, ptcp: connection reset by peer
        #c = self.net.addController('mycontroller', controller=RemoteController, ip='127.0.0.1', port=6653)
        os.system('ryu-manager /usr/local/python3.7.1/lib/python3.7/site-packages/ryu/app/simple_switch.py >./ryu-manager.log 2>&1 &')
        c = self.net.addController('mycontroller', controller=RemoteController, ip='0.0.0.0', port=6633)
        c.checkListening()
        controller_list.append(c)
        ovs = self.net.addSwitch('s999', cls=OVSSwitch)

        hostIpList = [
            host.ipAddress for host in self.topoObj.hosts if host is not None]

        j = 0
        ovslinks = []
        for i in range(self.topo.hostSum):
            if self.topo.mn_hosts[i] != None:
                ovslinks.append(self.net.addLink(self.net.hosts[j], ovs))
                #self.net.addLink(self.net.hosts[j], ovs)
                self.net.hosts[j].cmd(
                    "sysctl -w net.ipv6.conf.all.disable_ipv6=1")
                self.net.hosts[j].cmd(
                    "sysctl -w net.ipv6.conf.default.disable_ipv6=1")
                self.net.hosts[j].cmd(
                    "sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
                name = self.topoObj.hosts[i].name
                ipAddr = self.topoObj.hosts[i].ovsIpAddress
                ovslinks[-1].intf1.ip = ipAddr
                action = "ip addr add {}/24 broadcast 192.168.8.255 dev {}-eth1".format(ipAddr, name)
                self.net.hosts[j].cmd(action)
                self.net.hosts[j].cmd('ifconfig')
                j = j + 1

        # Use ovs-vsctl to add-br, add-port (between hosts and OVS switch), and set controller
        # It will be called when net.start()
        #ovs.start(controller_list)

        ## NOTE: Add normal port between localhost and OVS switch.
        ## This is important which correponds to connecting localhost to OVS Switch
        ## Only by doing it, localhost has the ARP table of OVS IPs of hosts in mininet
        ## Then, test.py can connect them by socket
        os.system('ip link add h-ens38 type veth peer name s-ens38')
        ##os.popen('ovs-vsctl add-port s999 s-ens38') 
        os.system('ifconfig s-ens38 up')
        os.system('ifconfig h-ens38 192.168.8.1/24')

        # Start controller, otherwise cannot connect controller when adding port to OVS switch
        self.net.start()
        os.system('ovs-vsctl add-port s999 s-ens38') 

        ## Add flow entries for MAC learning and ARP (ryu-controller/ovs-testcontroller do these things automatically)
        #for i in range(len(ovslinks)):
        #    hostmac = ovslinks[i].intf1.mac
        #    hostip = ovslinks[i].intf1.ip
        #    ovsport = i+1
            #os.system('ovs-ofctl add-flow s999 dl_dst={},actions=output:{}'.format(hostmac, ovsport))
        #os.system('ovs-ofctl add-flow s999 dl_type=0x800,nw_dst={},actions=output:{}'.format('192.168.8.1', len(ovslinks)+1))
        #os.system('ovs-ofctl add-flow s999 arp,actions=all')

        curdir = os.path.dirname(os.path.abspath(__file__))
        sysdir = os.path.dirname(curdir)

        j = 0
        if not os.path.exists('{}/packet/tmp'.format(sysdir)):
            os.mkdir('{}/packet/tmp'.format(sysdir))
        for i in range(self.topo.hostSum):
            if self.topo.mn_hosts[i] != None:
                log_filename = "{}/packet/tmp/h{}_send.txt".format(sysdir, i)
                packetSender = 'python3 {}/packet/sendint.py {} >{} 2>&1 &'.format(sysdir, i, log_filename)
                self.net.hosts[j].cmd(packetSender)

                log_filename = "{}/packet/tmp/h{}_recv.txt".format(sysdir, i)
                #intReceiver = '~/P4_DC/packet/receiveint ' + str(i) + ' >/dev/null &'
                intReceiver = 'python3 {}/packet/receive.py {} >{} 2>&1 &'.format(sysdir, i, log_filename)
                self.net.hosts[j].cmd(intReceiver)
                j = j + 1

    def getCLI(self):
        """
        Open Mininet CLI
        """
        CLI(self.net)

    def stopMnTopo(self):
        """
        Stop Mininet envirnoment
        """
        self.net.stop()

    def cleanMn(self):
        """
        Clean all mininet trace
        """
        os.system('sudo mn -c')
        os.system('sudo bash clear.sh')
        pass


if __name__ == '__main__':
    pass
