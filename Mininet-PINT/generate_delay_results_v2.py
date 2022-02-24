import math
import time
import sys
import numpy as np
import operator
import random
import os
import mmh3
import struct
from kll import KLL

random.seed(30)

class Element:
    def __init__(self, flow, node, approx_value):
        self.flow = flow
        self.node = node
        self.approx_value = float(approx_value)
    def __lt__(self, other):
        if self.flow != other.flow:
            return self.flow < other.flow
        if self.node != other.node:
            return self.node < other.node
        return self.approx_value < other.approx_value
    def __eq__(self, other):
        return self.flow == other.flow and self.node == other.node and self.approx_value == other.approx_value

# We follow PINT to deploy a KLL sketch with 100 digests for each flow and each node, so as to see how # of packets of a flow 
# at a node affects KLL sketch (not event as PINT samples packets which may not be reported)
def get_approx_res(approx_list, truth_list, packets):
    sampling_ratio = float(len(approx_list)) / float(len(truth_list))
    final_approx_list = approx_list.copy()
    final_truth_list = truth_list.copy()
    # Repeat the trace to simulate the increase of # of packets of a flow at a node
    if packets > len(truth_list):
        repeatnum = int(packets/len(truth_list))
        for _ in range(repeatnum):
            for truth in truth_list:
                final_truth_list.append(truth)
            for approx in approx_list:
                final_approx_list.append(approx)
        final_truth_list = final_truth_list[0:packets]
        final_approx_list = final_approx_list[0:int(packets*sampling_ratio)]

    sketch_size = 100
    kll = KLL(sketch_size)
    for v in final_approx_list:
        kll.update(float(v)) # v: latency

    min_diff_50 = 1000
    min_diff_99 = 1000
    tmp_median = 0
    tmp_tail = 0
    for (ii, quantile) in kll.cdf():
        diff = quantile - 0.5
        if diff < 0:
            diff = diff * -1
        if diff<min_diff_50:
            min_diff_50 = diff
            tmp_median = ii

        diff = quantile - 0.99
        if diff < 0:
            diff = diff * -1
        if diff<min_diff_99:
            min_diff_99 = diff
            tmp_tail = ii

    truth_median = np.median(final_truth_list)
    diff_median = abs(truth_median - tmp_median)
    if truth_median == 0:
        # Follow PINT
        #median_avgre = 0.0
        if int(tmp_median) == 0:
            median_avgre = 0.0
        else:
            median_avgre = 1.0
    else:
        median_avgre = float(diff_median) / float(truth_median)

    truth_tail = np.percentile(final_truth_list, 99)
    diff_tail = abs(truth_tail - tmp_tail)
    if truth_tail == 0:
        # Follow PINT
        #tail_avgre = 0.0
        if int(tmp_tail) == 0:
            tail_avgre = 0.0
        else:
            tail_avgre = 1.0
    else:
        tail_avgre = float(diff_tail) / float(truth_tail)

    return median_avgre, tail_avgre 

# Sketch
totalbytes = 1024 * 1024 # 1MB
hashnum = 1
width = int(totalbytes / (8 + 4) / hashnum)
def init_sketch():
    sketch = [] # [[(flowkey, latency)*width]*hashnum]
    for i in range(hashnum):
        sketch.append([])
        for j in range(width):
            sketch[i].append([-1, -1])
    return sketch
pernode_sketch_map = {} # {node, sketch}
def hash(flowkey):
    global width
    flowkey_bytes = struct.pack("L", flowkey)
    r = mmh3.hash(flowkey_bytes, signed=False)
    return r % width
def state_load(sketch, flowkey):
    global hashnum
    for row in range(hashnum):
        col = hash(flowkey)
        bucket = sketch[row][col]
        if bucket[0] == flowkey:
            return bucket[1]
    return None
def state_update(sketch, flowkey, latency):
    global hashnum
    for row in range(hashnum):
        col = hash(flowkey)
        bucket = sketch[row][col]
        bucket[0] = flowkey
        bucket[1] = latency

# Approximation
packets_range=[100, 500, 1000, 5000, 10000]
ap = 0.022 # We focus on 8 bits here
#all_approx=set() # Approximate coefficient
#approx_map={} # Approximate coefficiet -> bit number
#for bits in [4,8]:
#    if bits==4:
#        ap=0.42
#    if bits==8:
#        ap=0.022
#    all_approx.add(ap)
#    approx_map[ap]=bits

# Bandwidth cost
pint_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
dinto_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
dinte_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
complete_bitcost = 8 # original INT
#delta_threshold = 1
#delta_threshold = 2
#delta_threshold = 4
delta_threshold = 8
dint_complete_bitcost = 1 + complete_bitcost
dinto_delta_bitcost = 1
if delta_threshold == 1:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+2, 1+1
elif delta_threshold == 2:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+3, 1+1
elif delta_threshold == 4:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+4, 1+1
elif delta_threshold == 8:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+5, 1+1

### Trace replay ###

perflow_pernode_truth = {} # {flow, {node, [latency * pktnum]}}
pint_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
dinto_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
dinte_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
eventnum = 0

f=open("experiments/delays/processed_data","r")
for line in f:
    digests=line.strip().split(" ")
    flow = int(digests[0])
    seq = digests[1]
    node = int(digests[2])
    hopidx = int(digests[3])
    latency = int(digests[4])
    hopnum = int(digests[5])

    if flow not in perflow_pernode_truth:
        perflow_pernode_truth[flow] = {}
    if node not in perflow_pernode_truth[flow]:
        perflow_pernode_truth[flow][node] = []
    # PINT
    if flow not in pint_perflow_pernode_approx:
        pint_perflow_pernode_approx[flow] = {}
    if node not in pint_perflow_pernode_approx[flow]:
        pint_perflow_pernode_approx[flow][node] = []
    if flow not in pint_perpkt_bwcost_map:
        pint_perpkt_bwcost_map[flow] = {}
    if seq not in pint_perpkt_bwcost_map[flow]:
        pint_perpkt_bwcost_map[flow][seq] = []
    # DINTO/E
    if node not in pernode_sketch_map:
        pernode_sketch_map[node] = init_sketch()
    # DINTO
    if flow not in dinto_perflow_pernode_approx:
        dinto_perflow_pernode_approx[flow] = {}
    if node not in dinto_perflow_pernode_approx[flow]:
        dinto_perflow_pernode_approx[flow][node] = []
    if flow not in dinto_perpkt_bwcost_map:
        dinto_perpkt_bwcost_map[flow]  = {}
    if seq not in dinto_perpkt_bwcost_map[flow]:
        dinto_perpkt_bwcost_map[flow][seq] = []
    # DINTE
    if flow not in dinte_perflow_pernode_approx:
        dinte_perflow_pernode_approx[flow] = {}
    if node not in dinte_perflow_pernode_approx[flow]:
        dinte_perflow_pernode_approx[flow][node] = []
    if flow not in dinte_perpkt_bwcost_map:
        dinte_perpkt_bwcost_map[flow]  = {}
    if seq not in dinte_perpkt_bwcost_map[flow]:
        dinte_perpkt_bwcost_map[flow][seq] = []

    perflow_pernode_truth[flow][node].append(latency)

    # Value approximation (follow PINT)
    approx_value = 0
    if latency != 0:
        range_1=int(math.log(float(latency), (1+ap)**2))
        range_2=int(math.log(float(latency), (1+ap)**2)+0.5)
        approx_value_1=(1+ap)**(2*range_1)
        approx_value_2=(1+ap)**(2*range_2)
        diff_1=latency-approx_value_1
        if diff_1<0:
            diff_1=-1*diff_1
        diff_2=latency-approx_value_2
        if diff_2<0:
            diff_2=-1*diff_2
        if diff_1 <= diff_2:
            approx_value = int(approx_value_1)
        if diff_1 > diff_2:
            approx_value = int(approx_value_2)

    # PINT
    if (random.randint(1, 2) == 1) or (hopidx==hopnum-1): # Sampling by global hashing for PINT
        pint_perflow_pernode_approx[flow][node].append(approx_value)
        if hopidx == 0:
            pint_perpkt_bwcost_map[flow][seq].append([complete_bitcost])
        else:
            tmp_pint_prevbw = pint_perpkt_bwcost_map[flow][seq][-1][-1]
            pint_perpkt_bwcost_map[flow][seq][-1].append(tmp_pint_prevbw + complete_bitcost)
    else:
        if hopidx == 0:
            pint_perpkt_bwcost_map[flow][seq].append([0])
        else:
            tmp_pint_prevbw = pint_perpkt_bwcost_map[flow][seq][-1][-1]
            pint_perpkt_bwcost_map[flow][seq][-1].append(tmp_pint_prevbw + 0)

    # DINTO/E
    embedded_approx_value = state_load(pernode_sketch_map[node], flow)
    if ((embedded_approx_value is None) or (abs(approx_value - embedded_approx_value) > delta_threshold)):
        state_update(pernode_sketch_map[node], flow, approx_value)
        # DINTO
        dinto_perflow_pernode_approx[flow][node].append(approx_value)
        if hopidx == 0:
            dinto_perpkt_bwcost_map[flow][seq].append([dint_complete_bitcost])
        else:
            tmp_dinto_prevbw = dinto_perpkt_bwcost_map[flow][seq][-1][-1]
            dinto_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinto_prevbw + dint_complete_bitcost)
        # DINTE
        dinte_perflow_pernode_approx[flow][node].append(approx_value)
        if hopidx == 0:
            dinte_perpkt_bwcost_map[flow][seq].append([dint_complete_bitcost])
        else:
            tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
            dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dint_complete_bitcost)
    else:
        # DINTO
        dinto_perflow_pernode_approx[flow][node].append(embedded_approx_value)
        if hopidx == 0:
            dinto_perpkt_bwcost_map[flow][seq].append([dinto_delta_bitcost])
        else:
            tmp_dinto_prevbw = dinto_perpkt_bwcost_map[flow][seq][-1][-1]
            dinto_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinto_prevbw + dinto_delta_bitcost)
        # DINTE
        dinte_perflow_pernode_approx[flow][node].append(approx_value)
        if abs(approx_value - embedded_approx_value) == 0:
            if hopidx == 0:
                dinte_perpkt_bwcost_map[flow][seq].append([dinte_zero_delta_bitcost])
            else:
                tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
                dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dinte_zero_delta_bitcost)
        else:
            if hopidx == 0:
                dinte_perpkt_bwcost_map[flow][seq].append([dinte_nonzero_delta_bitcost])
            else:
                tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
                dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dinte_nonzero_delta_bitcost)

    # Latency measurement accuracy
    if hopidx == hopnum-1:
        eventnum += 1
    #if eventnum == packets:
    #    pint_median_avgre, pint_tail_avgre = get_approx_res(pint_perflow_pernode_approx, perflow_pernode_truth, packets)
    #    dinto_median_avgre, dinto_tail_avgre = get_approx_res(dinto_perflow_pernode_approx, perflow_pernode_truth, packets)
    #    dinte_median_avgre, dinte_tail_avgre = get_approx_res(dinte_perflow_pernode_approx, perflow_pernode_truth, packets)
    #    pint_median_avgre_list.append(pint_median_avgre)
    #    pint_tail_avgre_list.append(pint_tail_avgre)
    #    dinto_median_avgre_list.append(dinto_median_avgre)
    #    dinto_tail_avgre_list.append(dinto_tail_avgre)
    #    dinte_median_avgre_list.append(dinte_median_avgre)
    #    dinte_tail_avgre_list.append(dinte_tail_avgre)

        # Reset
    #    perflow_pernode_truth = {} # {flow, {node, [latency * pktnum]}}
    #    pint_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
    #    dinto_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
    #    dinte_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
    #    eventnum = 0
f.close()

#flow_list = []
#node_list = []
#perflow_pernode_eventnum = []
#for flow in perflow_pernode_truth.keys():
#    for node in perflow_pernode_truth[flow].keys():
#        flow_list.append(flow)
#        node_list.append(node)
#        perflow_pernode_eventnum.append(len(perflow_pernode_truth[flow][node]))
#perflow_pernode_eventnum_ranks = np.argsort(perflow_pernode_eventnum)
#topnum = 10 # Select the largest 10 flows
#top_flow_list, top_node_list = [], []
#for idx in perflow_pernode_eventnum_ranks[-topnum:]:
#    top_flow_list.append(flow_list[idx])
#    top_node_list.append(node_list[idx])

# For different packets
pint_median_final_avgre_list, pint_tail_final_avgre_list = [], []
dinto_median_final_avgre_list, dinto_tail_final_avgre_list = [], []
dinte_median_final_avgre_list, dinte_tail_final_avgre_list = [], []
for packets in packets_range:
    # For different flow-node keys
    pint_median_avgre_list, pint_tail_avgre_list = [], []
    dinto_median_avgre_list, dinto_tail_avgre_list = [], []
    dinte_median_avgre_list, dinte_tail_avgre_list = [], []
    #for i in range(len(top_flow_list)):
    #    flow = top_flow_list[i]
    #    node = top_node_list[i]
    for flow in perflow_pernode_truth.keys():
        for node in perflow_pernode_truth[flow].keys():
            if flow in pint_perflow_pernode_approx and node in pint_perflow_pernode_approx[flow]:
                pint_median_avgre, pint_tail_avgre = get_approx_res(pint_perflow_pernode_approx[flow][node], perflow_pernode_truth[flow][node], packets)
            else:
                pint_median_avgre, pint_tail_avgre = 1.0, 1.0
            if flow in dinto_perflow_pernode_approx and node in dinto_perflow_pernode_approx[flow]:
                dinto_median_avgre, dinto_tail_avgre = get_approx_res(dinto_perflow_pernode_approx[flow][node], perflow_pernode_truth[flow][node], packets)
            else:
                dinto_median_avgre, dinto_tail_avgre = 1.0, 1.0
            if flow in dinte_perflow_pernode_approx and node in dinte_perflow_pernode_approx[flow]:
                dinte_median_avgre, dinte_tail_avgre = get_approx_res(dinte_perflow_pernode_approx[flow][node], perflow_pernode_truth[flow][node], packets)
            else:
                dinte_median_avgre, dinte_tail_avgre = 1.0, 1.0
            pint_median_avgre_list.append(pint_median_avgre)
            pint_tail_avgre_list.append(pint_tail_avgre)
            dinto_median_avgre_list.append(dinto_median_avgre)
            dinto_tail_avgre_list.append(dinto_tail_avgre)
            dinte_median_avgre_list.append(dinte_median_avgre)
            dinte_tail_avgre_list.append(dinte_tail_avgre)

    # Accuracy
    pint_median_final_avgre = np.average(pint_median_avgre_list)
    pint_tail_final_avgre = np.average(pint_tail_avgre_list)
    dinto_median_final_avgre = np.average(dinto_median_avgre_list)
    dinto_tail_final_avgre = np.average(dinto_tail_avgre_list)
    dinte_median_final_avgre = np.average(dinte_median_avgre_list)
    dinte_tail_final_avgre = np.average(dinte_tail_avgre_list)
    pint_median_final_avgre_list.append(pint_median_final_avgre)
    pint_tail_final_avgre_list.append(pint_tail_final_avgre)
    dinto_median_final_avgre_list.append(dinto_median_final_avgre)
    dinto_tail_final_avgre_list.append(dinto_tail_final_avgre)
    dinte_median_final_avgre_list.append(dinte_median_final_avgre)
    dinte_tail_final_avgre_list.append(dinte_tail_final_avgre)

### Bandwidth cost ###

sum_pint_avgbitcost, sum_dinto_avgbitcost, sum_dinte_avgbitcost = 0, 0, 0

# PINT 
pktnum = 0
for flow, seq_bwcost_map in pint_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        runtimeidx = 0
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_pint_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
            runtimeidx += 1
pint_avgbitcost = float(sum_pint_avgbitcost) / float(pktnum)

# DeltaINT-O
pktnum = 0
for flow, seq_bwcost_map in dinto_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_dinto_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
dinto_avgbitcost = float(sum_dinto_avgbitcost) / float(pktnum)

# DeltaINT-E
pktnum = 0
for flow, seq_bwcost_map in dinte_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_dinte_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
dinte_avgbitcost = float(sum_dinte_avgbitcost) / float(pktnum)

print("[Average bit cost] PINT: {}, DeltaINT-O: {}, DeltaINT-E: {}".format(pint_avgbitcost, dinto_avgbitcost, dinte_avgbitcost))

print("[Average relative error]\n PINT median list: {}\n tail list: {}\n DeltaINT-O median list: {}\n tail list: {}\n DeltaINT-E median list: {}\n tail list: {}".format(\
        pint_median_final_avgre_list, pint_tail_final_avgre_list, dinto_median_final_avgre_list, dinto_tail_final_avgre_list, dinte_median_final_avgre_list, dinte_tail_final_avgre_list))




# Deprecated

def get_approx_res1(perflow_pernode_approx, perflow_pernode_truth, packets):
    # We use the same configuration of PINT which uses 100 digests per flow-node per 1000 events 
    # NOTE: PINT assumes that the trace comes from a single flow at a single node, while we distinguish different flows and nodes)
    flownodenum = 0
    for flow in perflow_pernode_truth.keys():
        for node in perflow_pernode_truth[flow].keys():
            flownodenum += 1
    #frac = max(math.log(float(flownodenum)*float(packets), 2)/math.log(1.0*1000.0, 2), float(packets)/100.0/2)
    #frac = float(packets) / 1000.0
    #frac = float(packets) / 100.0 / 2
    #sketch_size=int(100*frac) # KLL sketch size
    sketch_size = 100
    # Using sketch to store digests
    kll = KLL(sketch_size)
    for tmp_flow in perflow_pernode_approx.keys():
        for tmp_node in perflow_pernode_approx[tmp_flow].keys():
            for i in range(len(perflow_pernode_approx[tmp_flow][tmp_node])):
                v = Element(tmp_flow, tmp_node, perflow_pernode_approx[tmp_flow][tmp_node][i])
                kll.update(v) # v: flow-node-approx_value

    # Enumerate all elements in KLL sketch to get perflow pernode quantile latency
    tmp_perflow_pernode_estimation = {}
    for i in range(len(kll.compactors)):
        tmp_weight = 2**i
        for j in range(len(kll.compactors[i])):
            v = kll.compactors[i][j]
            tmp_flow, tmp_node, tmp_approx_value = v.flow, v.node, float(v.approx_value)
            if tmp_flow not in tmp_perflow_pernode_estimation:
                tmp_perflow_pernode_estimation[tmp_flow] = {}
            if tmp_node not in tmp_perflow_pernode_estimation[tmp_flow]:
                tmp_perflow_pernode_estimation[tmp_flow][tmp_node] = []
            for _ in range(tmp_weight):
                tmp_perflow_pernode_estimation[tmp_flow][tmp_node].append(tmp_approx_value)

    for flow in perflow_pernode_approx.keys():
        for node in perflow_pernode_approx[flow].keys():
            if flow not in tmp_perflow_pernode_estimation:
                tmp_perflow_pernode_estimation[flow] = {}
            if node not in tmp_perflow_pernode_estimation[flow]:
                tmp_perflow_pernode_estimation[flow][node] = [0.0]

    median_res = []
    tail_res = []
    for flow in perflow_pernode_truth.keys():
        for node in perflow_pernode_truth[flow].keys():
            truth_list = perflow_pernode_truth[flow][node]
            truth_median = np.median(truth_list)
            truth_tail = np.percentile(truth_list, 99)

            if flow not in tmp_perflow_pernode_estimation or node not in tmp_perflow_pernode_estimation[flow]:
                median_res.append(1.0)
                tail_res.append(1.0)
            else:
                estimation_list = tmp_perflow_pernode_estimation[flow][node]
                estimation_median = np.median(estimation_list)
                estimation_tail = np.percentile(estimation_list, 99)
                diff_median = abs(truth_median - estimation_median)
                diff_tail = abs(truth_tail - estimation_tail)
                if truth_median == 0:
                    # Follow PINT
                    median_res.append(0.0)
                    #if estimation_median == 0:
                    #    median_res.append(0.0)
                    #else:
                    #    median_res.append(1.0)
                else:
                    median_res.append(float(diff_median) / float(truth_median))
                if truth_tail == 0:
                    # Follow PINT
                    tail_res.append(0.0)
                    #if estimation_tail == 0:
                    #    tail_res.append(0.0)
                    #else:
                    #    tail_res.append(1.0)
                else:
                    tail_res.append(float(diff_tail) / float(truth_tail))

    median_avgre = sum(median_res) / float(len(median_res))
    tail_avgre = sum(tail_res) / float(len(tail_res))
    return median_avgre, tail_avgre

def get_approx_res2(perflow_pernode_approx, perflow_pernode_truth, packets):
    # We use the same configuration of PINT which uses 100 digests per flow-node per 1000 events 
    # NOTE: PINT assumes that the trace comes from a single flow at a single node, while we distinguish different flows and nodes)
    flownodenum = 0
    for flow in perflow_pernode_truth.keys():
        for node in perflow_pernode_truth[flow].keys():
            flownodenum += 1
    frac = max(math.log(float(flownodenum)*float(packets), 2)/math.log(1.0*1000.0, 2), float(packets)/100.0)
    sketch_size=100*frac # KLL sketch size

    total_pktnum = 0
    for flow in perflow_pernode_approx.keys():
        for node in perflow_pernode_approx[flow].keys():
            total_pktnum += len(perflow_pernode_approx[flow][node])
    tmp_perflow_pernode_estimation_median = {}
    tmp_perflow_pernode_estimation_tail = {}
    for flow in perflow_pernode_approx.keys():
        if flow not in tmp_perflow_pernode_estimation_median:
            tmp_perflow_pernode_estimation_median[flow] = {}
        if flow not in tmp_perflow_pernode_estimation_tail:
            tmp_perflow_pernode_estimation_tail[flow] = {}
        for node in perflow_pernode_approx[flow].keys():
            tmp_sketch_size = int(sketch_size * len(perflow_pernode_approx[flow][node]) / total_pktnum)
            if tmp_sketch_size == 0:
                continue
            tmp_kll = KLL(tmp_sketch_size)
            for v in pint_perflow_pernode_approx[flow][node]:
                tmp_kll.update(float(v)) # v: latency

            min_diff_50 = 1000
            min_diff_99 = 1000
            tmp_median = 0
            tmp_tail = 0
            for (ii, quantile) in tmp_kll.cdf():
                diff = quantile - 0.5
                if diff < 0:
                    diff = diff * -1
                if diff<min_diff_50:
                    min_diff_50 = diff
                    tmp_median = ii

                diff = quantile - 0.99
                if diff < 0:
                    diff = diff * -1
                if diff<min_diff_99:
                    min_diff_99 = diff
                    tmp_tail = ii
            tmp_perflow_pernode_estimation_median[flow][node] = tmp_median
            tmp_perflow_pernode_estimation_tail[flow][node] = tmp_tail

    median_res = []
    tail_res = []
    for flow in perflow_pernode_truth.keys():
        for node in perflow_pernode_truth[flow].keys():
            truth_list = perflow_pernode_truth[flow][node]
            truth_median = np.median(truth_list)
            truth_tail = np.percentile(truth_list, 99)

            if flow not in tmp_perflow_pernode_estimation_median or node not in tmp_perflow_pernode_estimation_median[flow]:
                median_res.append(1.0)
            else:
                diff_median = abs(truth_median - tmp_perflow_pernode_estimation_median[flow][node])
                if truth_median == 0:
                    # Follow PINT
                    median_res.append(0.0)
                else:
                    median_res.append(float(diff_median) / float(truth_median))

            if flow not in tmp_perflow_pernode_estimation_tail or node not in tmp_perflow_pernode_estimation_tail[flow]:
                tail_res.append(1.0)
            else:
                diff_tail = abs(truth_tail - tmp_perflow_pernode_estimation_tail[flow][node])
                if truth_tail == 0:
                    # Follow PINT
                    tail_res.append(0.0)
                else:
                    tail_res.append(float(diff_tail) / float(truth_tail))

    median_avgre = sum(median_res) / float(len(median_res))
    tail_avgre = sum(tail_res) / float(len(tail_res))
    return median_avgre, tail_avgre
