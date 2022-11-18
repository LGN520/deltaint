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

def genSpineLeafs(leafLayerNum):  # leafLayerNum must >= 1
    #sys.setrecursionlimit(1000000)
    #swSum = 3
    #topoLists = []

    # NOTE: SNum must be 6 (3, 9, 12, 15, ... cannot provide non-overlapping path, as only the last leaf layer can be the start nodes)
    swSum = 6

    L1 = int(swSum/3)
    L2 = L1*2

    totalSwnum = L1 + L2 * leafLayerNum
    print "totalSwnum for 1 spine layer + {} leaf layers: {}".format(leafLayerNum, totalSwnum)

    topoList = [[0 for i in range(totalSwnum)] for i in range(totalSwnum)]
    hostList = [0 for i in range(totalSwnum)]

    # topoList
    for i in range(L1): # spine layer
        for j in range(L1, swSum): # 1st leaf layer
            topoList[i][j] = 1
            topoList[j][i] = 1
    for leafLayerIdx in range(leafLayerNum-1): # leafLayerIdx-th leaf layer <-> (leafLayerIdx+1)-th leaf layer
        tmpStartSwidx = L1 + leafLayerIdx * L2
        tmpStartSwidxNextLayer = tmpStartSwidx + L2
        for pairIdx in range(L2/2): # L1 pairs
            for i in range(tmpStartSwidx + 2*pairIdx, tmpStartSwidx + 2*(pairIdx + 1)):
                for j in range(tmpStartSwidxNextLayer + 2*pairIdx, tmpStartSwidxNextLayer + 2*(pairIdx + 1)):
                    topoList[i][j] = 1
                    topoList[j][i] = 1

    # hostList
    for i in range(totalSwnum - L2, totalSwnum):
        hostList[i] = 1

    # pathList
    pathList = []
    i = totalSwnum - L2
    if L1 != 2:
        print "[ERROR] cannot provide non-overlappig path for L1 = {} != 2, as only hosts can be the start nodes".format(L1)
        exit(-1)
    isMultiLeafLayer = False
    if leafLayerNum > 1:
        isMultiLeafLayer = True
    while True:
        if i >= totalSwnum:
            break
        for j in range(L1): # NOTE: L1 must be 2
            path = [i]
            if j == 0: # Straight-line path
                tmpLeafLayerIdx = leafLayerNum - 2
                while isMultiLeafLayer:
                    if tmpLeafLayerIdx < 0:
                        break
                    tmpDeltaLayerNum = (leafLayerNum -1) - tmpLeafLayerIdx
                    path.append(i - L2 * tmpDeltaLayerNum)
                    tmpLeafLayerIdx -= 1
                path.append(j)
                tmpLeafLayerIdx = 0
                while isMultiLeafLayer:
                    if tmpLeafLayerIdx >= leafLayerNum - 1:
                        break
                    tmpDeltaLayerNum = (leafLayerNum -1) - tmpLeafLayerIdx
                    path.append(i + 1 - L2 * tmpDeltaLayerNum)
                    tmpLeafLayerIdx += 1
            elif j == 1: # Snake path
                tmpLeafLayerIdx = leafLayerNum - 2
                while isMultiLeafLayer:
                    if tmpLeafLayerIdx < 0:
                        break
                    tmpDeltaLayerNum = (leafLayerNum -1) - tmpLeafLayerIdx
                    if tmpDeltaLayerNum % 2 == 1:
                        path.append(i + 1 - L2 * tmpDeltaLayerNum)
                    else:
                        path.append(i - L2 * tmpDeltaLayerNum)
                    tmpLeafLayerIdx -= 1
                path.append(j)
                tmpLeafLayerIdx = 0
                while isMultiLeafLayer:
                    if tmpLeafLayerIdx >= leafLayerNum - 1:
                        break
                    tmpDeltaLayerNum = (leafLayerNum -1) - tmpLeafLayerIdx
                    if tmpDeltaLayerNum % 2 == 1:
                        path.append(i - L2 * tmpDeltaLayerNum)
                    else:
                        path.append(i + 1 - L2 * tmpDeltaLayerNum)
                    tmpLeafLayerIdx += 1
            else:
                print "[ERROR] invalid j {}".format(j)
                exit(-1)
            path.append(i + 1)
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
    k = int(sys.argv[1]) # k: leaf layer num
    #topoList1, hostList1 = genFatTree(10) #maxSNum must be larger than 10
    #print(topoList1)
    #print(hostList1)
    topoList, hostList, pathList = genSpineLeafs(k) # SNum must be 6
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

