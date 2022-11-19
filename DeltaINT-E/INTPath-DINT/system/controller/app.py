#!/usr/bin/env python2
# -*- coding:utf-8 -*-

import os
import sys
#sys.path.append("/home/ssy/behavioral-model/tools")
#sys.path.append("/home/ssy/behavioral-model/targets/simple_switch")
sys.path.append("/home/sysheng/behavioral-model/tools")
sys.path.append("/home/sysheng/behavioral-model/targets/simple_switch")

from device import Switch, Host
#from routeFinding import RouteFinding
#from switchRuntime import SwitchRuntime
#from topoMaker import TopoMaker
from topoMaker import TopoMaker # Support large network scale
#from dBParser import DBParser

import copy
import socket
import json
import time
import subprocess
from mininet.cli import CLI


_ = float('inf')

#bmv2_path = "/home/ssy/behavioral-model/targets/simple_switch"
bmv2_path = "/home/sysheng/behavioral-model/targets/simple_switch"

with open("../config.json", "r") as f:
    app_config = json.load(f)

class Ctrl(object):
    """
    The controller's main control flow class.
    """

    def __init__(self, switchGraph, hostList):
        """
        Constructor, use switch graph and host list generate or initialize some instance variables or algorithm, and calculate some variables
        varibles list
        switchGraph: a two-dimension graph to describe the origin network
        graph: a two-dimension graph to describe the current network situation
        vertexNum: the switch num in the network
        routeFinding: initial the route finding algorithm with switch graph
        hostList: the list of which switch has a host

        hosts: hosts in network
        switches: switches in network
        oldGraph: never used
        oldSwitchList: never used
        socketList: socket links to each host in network
        socketPort: the specific port num to generate the link hosts in netwrok
        nowActId: the number of actions from AI
        dbInfo: the database connection information
        dbParser: initial the database parser with switch number and database connection information

        qdepth: the queue depth in network
        qrate: the queue rate in network
        qratesmall: (temporatory) a smaller queue rate in netwrok

        :param switchGraph:  a two-dimension graph to describe a network
        :param hostList: a one-dimension list to describe which switch in network has a host connection
        """

        self.switchGraph = copy.deepcopy(switchGraph)
        self.graph = switchGraph
        self.vertexNum = len(switchGraph)
        self.hostList = hostList
        self.switchList = [1] * self.vertexNum
        self.hosts = []
        self.switches = []
        self.oldGraph = []
        self.oldSwitchList = []
        self.socketList = []
        self.nowActId = 0
        #self.dbParser = DBParser(self.vertexNum, self.dbInfo, self.switches)
        self.socketPort = 8888
        #self.paths = paths

    def getSwitchByName(self, name):
        """
        Get a switch in switch list by its name

        :param name: switch name, such as s1
        :returns: a switch instance
        """
        return self.switches[int(name[1:])]

    def getHostByName(self, name):
        """
        Get a host in host list by its name

        :param name: host name, such as h1
        :returns: a host instance
        """
        return self.hosts[int(name[1:])]

    def genMac(self, id):
        """
        Generate a MAC address by device id

        only support host id and must form 0 to 255 now

        :param id: device id
        :returns: a MAC address calculated by device id
        """
        # only support id form 0 to 255 now
        macPrefix = '00:01:00:00:00:'
        hexId = hex(id)[2:].upper()
        if len(hexId) == 1:
            hexId = '0' + hexId
        mac = macPrefix + hexId
        return mac

    def genIp(self, id, isOvs=False):
        """
        Generate a IP address by device id

        only support host id and must form 0 to 255 now

        :param id: device id
        :param isOvs: indicate the device is OpenVSwitch or P4 host
        :returns: a IP address calculated by device id
        """
        # only support id form 0 to 255 now
        if isOvs:
            ipPrefix = '192.168.8.'
        else:
            ipPrefix = '10.0.0.'
        ip = ipPrefix + str(id + 100)
        return ip

    def genDevice(self):
        """
        Generate logical device instance and add thrift link to host
        """
        for i in range(self.vertexNum):
            thriftPort = 9090 + i
            self.switches.append(
                #Switch('s' + str(i), thriftPort, SwitchRuntime(thriftPort=thriftPort)))
                Switch('s' + str(i), thriftPort, None))
            if self.hostList[i] == 1:
                self.hosts.append(
                    Host('h' + str(i), self.genMac(i), self.genIp(i), self.genIp(i, True)))
            else:
                self.hosts.append(None)

    def genLinks(self):
        """
        Generate logical links to devices
        """
        for i in range(self.vertexNum):
            for j in range(i + 1, self.vertexNum):
                if self.graph[i][j] == 1:
                    self.switches[i].addLink('s' + str(j))
                    self.switches[j].addLink('s' + str(i))

        for i in range(self.vertexNum):
            if self.hostList[i] == 1:
                self.hosts[i].addLink('s' + str(i))
                self.switches[i].addLink('h' + str(i))

    def genArpTable(self):
        """
        Generate arp table and add to each switches logically
        """
        #arpList = [('doarp', 'arpreply', ('00:00:00:00:00:00', host.ipAddress), host.macAddress)
        #           for host in self.hosts if host is not None]
        arpList = [('doarp', 'arpreply', host.ipAddress, host.macAddress)
                   for host in self.hosts if host is not None]
        for i in range(self.vertexNum):
            self.switches[i].tables = self.switches[i].tables + arpList

    def getDevPortByName(self, deviceName, nextDeviceName):
        """
        Get a device port on one device which is linked to another specified device

        :param deviceName: the device name to calculate the port
        :param nextDeviceName the name of device which the port linked to
        """
        devices = None
        deviceType = deviceName[0:1]
        deviceId = int(deviceName[1:])
        if deviceType == 's':
            devices = self.switches
        elif deviceType == 'h':
            devices = self.hosts
        if devices:
            device = devices[deviceId]
            for port in device.ports:
                if port.deviceName == nextDeviceName:
                    return port.portNum
        return None

    def genRouteInfoViaPort(self, portsList):
        """
        Generate source route info string by a list of ports on each switch

        :param portsList: a route port list for source routeing
        :returns: a info string for source routing
        """
        portStr = ''
        for port in portsList:
            binPort = bin(port)[2:]
            for i in range(4 - len(binPort) % 4):
                binPort = str(0) + binPort
            portStr = portStr + binPort
        portStr = hex(int(portStr, 2))
        return portStr

    def genDeviceNoTable(self):
        """
        Generate device number table to switches

        the device number is used to indicate the switch itself
        """
        for id, switch in enumerate(self.switches):
            tableItem = ('setmetadata', 'setdeviceno', '', id+1) # Start from 1
            switch.tables.append(tableItem)

    def getTableInfo(self):
        """
        Get all tables in all switches
        :returns: a table list for all tables
        """
        tables = []
        for switch in self.switches:
            tables.append(switch.tables)
        return tables

    def genTables(self, doClear=False):
        """
        Generate trans table with route list and push arplist to all switches and send information to front end
        :param doClear: clear old tables in all switches logically or not
        """
        if doClear:
            for switch in self.switches:
                switch.tables = []
        self.genArpTable()
        self.genDeviceNoTable()

    def downTables(self, doClear=False):
        """
        Down all tables to all the switched in the true network
        :param doClear: clear old tables in all switches truely or not
        """
        curdir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.exists("{}/tmp".format(curdir)):
            os.mkdir("{}/tmp".format(curdir))
        for switch in self.switches:
            if doClear:
                rule_filename = "{}/tmp/{}_clear.txt".format(curdir, switch.name)
            else:
                rule_filename = "{}/tmp/{}.txt".format(curdir, switch.name)
            rule_fd = open(rule_filename, "w+")
            if doClear:
                #switch.runtime.table_clear('dotrans')
                rule_fd.write('table_clear dotrans\n')
            for table in switch.tables:
                tableName = table[0]
                actionName = table[1]
                keys = table[2]
                values = table[3]
                #switch.runtime.table_add(tableName, actionName, keys, values)
                rule_fd.write('table_add {} {} {} => {}\n'.format(tableName, actionName, keys, values))
            rule_fd.flush()
            rule_fd.close()
            os.system("sudo {}/simple_switch_CLI --thrift-port {} < {}".format(bmv2_path, switch.thriftPort, rule_filename))

    def makeTopo(self):
        """
        Build the true netwrok using the informatin in controller and change queue depth/rate in switches
        """
        curdir = os.path.dirname(os.path.abspath(__file__))
        sysdir = os.path.dirname(curdir)
        #switchPath = '/home/ssy/behavioral-model/targets/simple_switch/simple_switch'
        switchPath = '/home/sysheng/behavioral-model/targets/simple_switch/simple_switch'
        if app_config["is_dump"] == "1":
            jsonPath = "{}/p4app/dump_app.json".format(sysdir)
        elif app_config["method"] == "INT-Path":
            jsonPath = '{}/p4app/app.json'.format(sysdir) # INT-Path
        elif app_config["method"] == "DeltaINT":
            jsonPath = '{}/p4app/dint_app.json'.format(sysdir) # DINT
            #jsonPath = '{}/p4app/dint_app2.json'.format(sysdir) # DINT hashnum=2
            #jsonPath = '{}/p4app/dint_app3.json'.format(sysdir) # DINT hashnum=3
            #jsonPath = '{}/p4app/dint_app4.json'.format(sysdir) # DINT hashnum=4
            #jsonPath = '{}/p4app/simple_dint_app.json'.format(sysdir) # DINT without sketching
        elif app_config["method"] == "DeltaINTExt":
            jsonPath = '{}/p4app/dintext_app.json'.format(sysdir) # DINT-E
        else:
            print("Invalid method in config.json {} which should be INT-Path or DeltaINT".format(app_config["method"]), flush=True)
            exit(-1)
        self.topoMaker = TopoMaker(switchPath, jsonPath, self)
        #self.topoMaker.cleanMn()
        self.topoMaker.genMnTopo()
        for i, switch in enumerate(self.switches):
            qdepth = 1024*1024 # 1M pkts
            qrate = 10*1024*1024 # 10M pps
            #switch.runtime.makeThriftLink(qdepth, qrate)

    def genHostLink(self, host):
        """
        Make socket link to a specific host in the true network
        :param host: the host to make socket link
        """
        try:
            print(host.ovsIpAddress, self.socketPort, 'connecting')
            socketLink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketLink.connect((host.ovsIpAddress, self.socketPort))
            return socketLink
        except socket.error as e:
            print('socket gen failed: {}'.format(e), host.name)
            return None

    def genSocketLinkToHosts(self):
        """
        Make socket links to all hosts in the network
        """
        self.socketList = []
        print('start connect')
        for host in self.hosts:
            if host:
                # Use ovslink instead of bmv2link
                print('connecting ', host.ovsIpAddress)
                socketLink = self.genHostLink(host)
                print(host.ovsIpAddress, 'connected')
                self.socketList.append(socketLink)
            else:
                self.socketList.append(None)

    def sendInfoViaSocket(self, hostId, sendType, info):
        """
        Send information to host in true network with the socket establish before
        :param hostId: the host to send information
        :param sendType: the information type
        :param info: the information content
        :returns: the send status (success=>True/failed=>False)
        """
        def sendInfo(sendType, info):
            socketLink.send(json.dumps({
                'type': sendType,
                'info': info
            }).encode('utf-8'))

        socketLink = self.socketList[hostId]
        if socketLink:
            try:
                sendInfo(sendType, info)
            except:
                time.sleep(5)
                socketLink = self.genHostLink(self.hosts[hostId])
                sendInfo(sendType, info)
                pass
            return True
        return False

    def traversePaths(self, paths, sendTimes=3):
        """
        Traverse all path using source routing to get all information in network use INT
        generate traverse info and send it to host by socket link
        :param paths: traverse path from AI
        """
        startNodeDict = {}
        for path in paths:
            startNodeDict[path[0]] = {
                'portsLists': [],
                'addressList': []
            }
        for path in paths:
            portsList = [self.getDevPortByName(
                's' + str(path[i]), 's' + str(path[i + 1])) for i in range(len(path) - 1)]
            portsList.append(self.getDevPortByName(
                's' + str(path[len(path) - 1]), 'h' + str(path[len(path) - 1])))
            # print('path', path)
            # print('portsList', portsList)
            address = self.hosts[path[len(path) - 1]].ipAddress
            startNode = path[0]
            startNodeDict[startNode]['portsLists'].append(portsList)
            startNodeDict[startNode]['addressList'].append(address)
        for key, sendObj in startNodeDict.items():
            # print('portslists', key, sendObj['portsLists'])
            self.sendInfoViaSocket(key, 'TraversePath', {
                'portsLists': sendObj['portsLists'],
                'addressList': sendObj['addressList'],
                'actId': self.nowActId,
                'sendTimes': sendTimes
            })

    def start(self):
        """
        Use the given topo and hosts start the experiment envirnoment

        generate devices, links, tables
        then generate the mininet network, link host with socket,
        then send information to front end

        :returns: True
        """
        self.genDevice()
        self.genLinks()
        self.genTables()
        #self.dumpPaths()
        self.makeTopo() # Mininet has started
        self.downTables()
        # Sockets from controller to hosts, connect each host to trigger INT
        self.genSocketLinkToHosts()

        return True

    def updateGraphByAction(self, action):
        """
        Update the topology in network by switch ID

        :param action: action switch ID(positive means open a switch, negative means close a switch, zero means no action, id is larger than actual 1)
        :returns: Boolen (True means an action had done, False means no action been done)
        """
        close = False
        if action == 0:
            return False
        elif action < 0:
            action = -action
            # xiaoyujie's start id is 1
            self.switchList[action - 1] = 0
            close = True
        else:
            self.switchList[action - 1] = 1

        for i in range(self.vertexNum):
            if i != action - 1:
                if close:
                    self.graph[i][action - 1] = _
                    self.graph[action - 1][i] = _
                else:
                    self.graph[i][action - 1] = self.switchGraph[i][action - 1]
                    self.graph[action - 1][i] = self.switchGraph[action - 1][i]

        return True

    def update(self, action=None, paths=None, times=None):
        """
        Receive parameters from AI, then update topology and traverse all INT path, last, get the rewardMatrix and send it to AI and front end

        :param action: action switch ID
        :param paths: path switch ID lists (the switches who need to do INT)
        :returns: rewardMatrix (the matrix contains link queue depth per route)
        """
        self.nowActId = self.nowActId + 1
        print('now act id ', self.nowActId)
        #rewardMatrix = None
        # print('action', action)
        if action:
            if self.updateGraphByAction(action):
                self.genTables(True)
                self.downTables(True)
        time.sleep(1)
        if paths:
            if times:
                self.traversePaths(paths, times)
            else:
                self.traversePaths(paths)
            #time.sleep(10)
            #rewardMatrix = self.dbParser.parser(self.nowActId)

        #return rewardMatrix


if __name__ == '__main__':
    #graph = [
    #    [0, 1, 1, _, _, _],
    #    [1, 0, 1, 1, _, _],
    #    [1, 1, 0, 1, 1, _],
    #    [_, 1, 1, 0, 1, 1],
    #    [_, _, 1, 1, 0, 1],
    #    [_, _, _, 1, 1, 0],
    #]
    # only support one host per switch
    #hostList = [1, 1, 1, 0, 1, 1]

    print("*********** START ***********")

    print("\nLoad topology...")
    fd = open("./topology.json", "r")
    jsonobj = json.load(fd)
    fd.close()
    graph = jsonobj["topoList"]
    hostList = jsonobj["hostList"]
    paths = jsonobj["pathList"]
    #print("Graph: {}".format(graph))
    #print("hostList: {}".format(hostList))
    #print("pathList: {}".format(paths))

    print("\nCreate topology...")
    app = Ctrl(graph, hostList)
    app.start()

    print("\nStart INT ...")
    #paths = [[0, 1, 2], [0, 2, 3]]
    #app.update(-1, paths)
    #paths = [[0, 1, 3, 5], [0, 2, 4, 5], [1, 2, 3, 4]]
    #paths = [[0,1,2]]
    app.update(0, paths, 10) # Enable source hosts to send INT-packets continuously within 10 s
    time.sleep(2)

    if app_config["is_dump"] == "0" and app_config["is_detect"] == "1": # Skip this block when testing bandwidth overhead
        print("\nOpen detector...")
        #os.system("python3 detector.py >detector.log 2>&1 &")
        fd = open("detector.log", "w+")
        proc = subprocess.Popen(["python3", "detector.py", "&"], stdout=fd, stderr=fd, shell=False)
        time.sleep(1)

        if app_config["is_linkdown"] == "1":
            print("\nSimulate link down ...")
            snode_name = app.switches[0].name
            for j in range(len(graph[0])):
                if graph[0][j] == 1:
                    break
            dnode_name = app.switches[j].name
            print("Cut down link between {} and {}, TIME {}".format(snode_name, dnode_name, time.time()), flush=True)
            app.topoMaker.net.configLinkStatus(snode_name, dnode_name, "down")
        else:
            print("\nSimulate latency ...")
            curdir = os.path.dirname(os.path.abspath(__file__))
            for i in range(len(app.hosts)):
                if app.hosts[i] is not None:
                    break
            node_name = app.hosts[i].name
            eport = 1
            timedelta = int(app_config["latency_threshold"])*128
            rule_filename = "{}/tmp/simulate_latency.txt".format(curdir)
            fd2 = open(rule_filename, "w+")
            fd2.write("table_add set_timedelta_tbl set_timedelta {} => {}\n".format(eport, timedelta))
            fd2.flush()
            fd2.close()
            print("Simluate latency in switch {} egress port {}, TIME {}".format(app.switches[i].name, eport, time.time()), flush=True)
            os.system("sudo {}/simple_switch_CLI --thrift-port {} < {}".format(bmv2_path, app.switches[i].thriftPort, rule_filename))

    time.sleep(20)
    #CLI(app.topoMaker.net)

    print("*********** END ***********")

    print("\nClear OVS Switch, Mininet, Controller, and Detector...")
    app.topoMaker.cleanMn()
    if app_config["is_dump"] == "0" and app_config["is_detect"] == "1":
        proc.terminate()
        fd.close()
