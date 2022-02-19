#!/usr/bin/env python3

import os
import mmh3
import struct

## Global variables

dirname = "../packet/tmp"
filenames = ["h4_dump.txt", "h6_dump.txt", "h8_dump.txt"]
thresholds = [0, 0, 0, 1] # deiveno, iport, eport, timedelta
delta_bits = [1, 1, 1, 1+2] # Threshold=1 for delta encoding in DeltaINT-ext
#thresholds = [0, 0, 0, 4] # deiveno, iport, eport, timedelta
#delta_bits = [1, 1, 1, 1+4] # Threshold=2 for delta encoding in DeltaINT-ext
#thresholds = [0, 0, 0, 16] # deiveno, iport, eport, timedelta
#delta_bits = [1, 1, 1, 1+6] # Threshold=4 for delta encoding in DeltaINT-ext
#thresholds = [0, 0, 0, 64] # deiveno, iport, eport, timedelta
#delta_bits = [1, 1, 1, 1+8] # Threshold=8 for delta encoding in DeltaINT-ext
complete_bits = [1+8, 1+8, 1+8, 1+32]
statenum = len(thresholds)
hopnum = 3
switchnum = 9 # Device number from 1 to 9

totalbytes = 1024 * 1024 # 1MB
hashnum = 1
width = int(totalbytes / (2 + 3 + 4) / hashnum)

DINT_BW = 0
dint_prevbw = 0
dint_truth_cnt = 0
dint_collect_cnt = 0
dint_truth_collect_cnt = 0

DINTEXT_BW = 0
dintext_prevbw = 0
dintext_truth_cnt = 0
dintext_collect_cnt = 0
dintext_truth_collect_cnt = 0

## Util functions

def init_sketches():
    global switchnum, hashnum, width
    sketches = []
    for _ in range(switchnum):
        sketches.append([])
        sketch = sketches[-1]
        for i in range(hashnum):
            sketch.append([])
            for j in range(width):
                sketch[i].append([-1, -1, -1, -1, -1]) # flowkey, deviceno, iport, eport, timedelta
    return sketches

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
            return bucket[1:5]
    return None

def delta_calc(curstates, recstates):
    global thresholds
    global dint_prevbw, dintext_prevbw, DINT_BW, DINTEXT_BW
    global dint_truth_cnt, dint_collect_cnt, dint_truth_collect_cnt
    global dintext_truth_cnt, dintext_collect_cnt, dintext_truth_collect_cnt
    global debug_a, debug_b
    results = []
    for i in range(len(curstates)):
        if recstates[i] != -1 and abs(curstates[i] - recstates[i]) <= thresholds[i]:
            results.append(recstates[i])
            dint_prevbw += 1
            if abs(curstates[i] - recstates[i]) == 0:
                dintext_prevbw += (1 + 1)
                dint_truth_collect_cnt += 1
            else:
                dintext_prevbw += delta_bits[i]
        else:
            results.append(curstates[i])
            dint_prevbw += complete_bits[i]
            dintext_prevbw += complete_bits[i]
            dint_truth_collect_cnt += 1
        dint_truth_cnt += 1
        dint_collect_cnt += 1
        dintext_truth_cnt += 1
        dintext_collect_cnt += 1
        dintext_truth_collect_cnt += 1
    DINT_BW += dint_prevbw
    DINTEXT_BW += dintext_prevbw
    return results

def state_update(sketch, flowkey, outputs):
    global hashnum
    for row in range(hashnum):
        col = hash(flowkey)
        bucket = sketch[row][col]
        bucket[0] = flowkey
        for i in range(len(outputs)):
            bucket[i+1] = outputs[i]

def accuracy_calc(curstates, outputs):
    res = []
    # Only consider dynamic states
    for i in range(len(curstates)):
        if i != len(curstates) - 1:
            if curstates[i] == outputs[i]:
                re = 0.0
            else:
                re = 1.0
            #continue
        else:
            if curstates[i] != 0:
                re = abs(curstates[i] - outputs[i]) / float(curstates[i])
            else:
                if outputs[i] == 0:
                    re = 0.0
                else:
                    re = 1.0
        res.append(re)
    return res

global_res = []
pktcnt = 0
complete_num = 0
equal_num = 0
larger_num = 0
smaller_num = 0
for filename in filenames:
    sketches = init_sketches()
    filepath = os.path.join(dirname, filename)
    fd = open(filepath, "r")
    while True:
        line = fd.readline().strip()
        if line == "":
            break
        entries = line.split(" ")
        for i in range(len(entries)):
            entries[i] = int(entries[i])

        flowkey = entries[0]
        intlist = []
        for idx in range(hopnum):
            base = statenum * idx
            # device numter, iport, eport, timedelta
            intlist.append([entries[base+1], entries[base+2], entries[base+3], entries[base+4]])

        dint_prevbw = 0
        dintext_prevbw = 0
        pktcnt += 1
        for idx in range(hopnum):
            switchidx = intlist[idx][0] - 1 # device number - 1
            sketch = sketches[switchidx]
            recstates = state_load(sketch, flowkey)
            if recstates is None:
                complete_num += 1 # No embedded state -> directly update stateful memory without need for recirculation
            else:
                for i in range(len(intlist[idx])):
                    if intlist[idx][i] == recstates[i]:
                        equal_num += 1
                    elif intlist[idx][i] > recstates[i]:
                        larger_num += 1
                    else:
                        smaller_num += 1
            if recstates is not None:
                outputs = delta_calc(intlist[idx], recstates)
            else:
                outputs = intlist[idx]
                for i in range(len(intlist[idx])):
                    dint_prevbw += complete_bits[i]
                    dintext_prevbw += complete_bits[i]
                    DINT_BW += dint_prevbw
                    DINTEXT_BW += dintext_prevbw
                    dint_truth_cnt += 1
                    dint_collect_cnt += 1
                    dintext_truth_cnt += 1
                    dintext_collect_cnt += 1
                    dint_truth_collect_cnt += 1
                    dintext_truth_collect_cnt += 1
            state_update(sketch, flowkey, outputs)
            res = accuracy_calc(intlist[idx], outputs)
            global_res += res

    fd.close()

dint_avgbit = float(DINT_BW) / float(pktcnt) / float(hopnum)
dintext_avgbit = float(DINTEXT_BW) / float(pktcnt) / float(hopnum)
print("Average bit cost of DINT: {} DINT-ext: {}".format(dint_avgbit, dintext_avgbit))

dint_precision = float(dint_truth_collect_cnt) / float(dint_collect_cnt)
dint_recall = float(dint_truth_collect_cnt) / float(dint_truth_cnt)
print(dint_collect_cnt, dint_truth_cnt, dint_truth_collect_cnt)
print("DINT precision: {} recall: {}".format(dint_precision, dint_recall))

dintext_precision = float(dintext_truth_collect_cnt) / float(dintext_collect_cnt)
dintext_recall = float(dintext_truth_collect_cnt) / float(dintext_truth_cnt)
print("DINT-ext precision: {} recall: {}".format(dintext_precision, dintext_recall))

print("complete_num: {}, equal_num: {}, larger_num: {}, smaller_num: {}, sum: {}".format(complete_num, equal_num, larger_num, smaller_num, complete_num + equal_num + larger_num + smaller_num))

#avg_re = sum(global_res) / float(len(global_res))
#print("Average relative error of measurement accuracy of states: {}".format(avg_re))
