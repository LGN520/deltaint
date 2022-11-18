#!/usr/bin/python
import sys
import copy
import json

def genFatTree(swSum):  #SNum must be 10,15,20,25,30...
    #sys.setrecursionlimit(1000000)
    #swSum = 10
    #topoLists = []

    L1 = int(swSum/5)
    L2 = L1*2
    L3 = L2

    topoList = [[0 for i in range(swSum)] for i in range(swSum)]
    hostList = [0 for i in range(swSum)]
    linkNum = 0

    core = [0 for i in range(L1)]
    agg = [0 for i in range(L2)]
    edg = [0 for i in range(L3)]

    # add core switches
    for i in range(L1):
        core[i] = i

    # add aggregation switches
    for i in range(L2):
        agg[i] = L1 + i

    # add edge switches
    for i in range(L3):
        edg[i] = L1 + L2 + i

    # add links between core and aggregation switches
    for i in range(L1):
        for j in agg[:]:
            topoList[core[i]][j] = 1
            topoList[j][core[i]] = 1
            linkNum += 2

    # add links between aggregation and edge switches
    for step in range(0, L2, 2):
        for i in agg[step:step+2]:
            for j in edg[step:step+2]:
                    topoList[i][j] = 1
                    topoList[j][i] = 1
                    linkNum += 2

    # hostList
    for i in range((L1+L2), swSum):
        hostList[i] = 1

    return topoList, hostList

def genSpineLeaf(swSum):  #SNum must be 3,6,9,12,15...
    #sys.setrecursionlimit(1000000)
    #swSum = 3
    #topoLists = []

    L1 = int(swSum/3)
    L2 = L1*2

    topoList = [[0 for i in range(swSum)] for i in range(swSum)]
    hostList = [0 for i in range(swSum)]

    # topoList
    for i in range(L1):
        for j in range(L1, swSum):
            topoList[i][j] = 1
            topoList[j][i] = 1

    # hostList
    for i in range(L1, swSum):
        hostList[i] = 1

    # pathList
    pathList = []
    i = L1
    while True:
        if i >= swSum:
            break
        for j in range(L1):
            path = [i, j, i+1]
            pathList.append(path)
        i += 2

    return topoList, hostList, pathList

def calOddNum(topoMatrix, sNum):
    count = 0
    for i in range(sNum):
        degreeSum = 0
        for j in range(sNum):
            degreeSum += topoMatrix[i][j]
        if degreeSum%2 == 1:
            count += 1
    return count

if __name__ == '__main__':
    k = int(sys.argv[1]) # k: spine switch num
    #topoList1, hostList1 = genFatTree(10) #maxSNum must be larger than 10
    #print(topoList1)
    #print(hostList1)
    topoList, hostList, pathList = genSpineLeaf(3*k) #SNum must be larger than 3
    #print(topoList)
    #print(hostList)
    #print(pathList)
    jsonobj = {}
    jsonobj["topoList"] = topoList
    jsonobj["hostList"] = hostList
    jsonobj["pathList"] = pathList
    #print(jsonobj)
    fd = open("./topology.json", "w")
    json.dump(jsonobj, fd)
    fd.close()

