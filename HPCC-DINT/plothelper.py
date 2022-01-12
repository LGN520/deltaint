import sys

if len(sys.argv) != 3:
    print("Example: python3 plothelper.py simulation/mix/DINT_cur_alwaysdelta_5/DINT_fb.out 1")
    exit(-1)

filepath = sys.argv[1]
threshold = int(sys.argv[2])
deltabits = {1: 1+2, 2: 1+3, 4: 1+4, 8: 1+5}
if threshold not in deltabits.keys():
    print("Invalid threshold!")
    exit(-1)
fd = open(filepath, "r")

valid_linenum = 0
datamap = {}
while True:
    line = fd.readline()
    if line == "":
        break

    line = line.strip()
    elements = line.split()
    if elements[0] == "Host":
        valid_linenum += 1
        hostid = elements[1] # E.g., [268]:
        hostid = hostid[1:len(hostid)-2] # E.g., 268
        save_hopnum = elements[4] # E.g., 100,
        save_hopnum = int(save_hopnum[0:len(save_hopnum)-1]) # E.g., 100
        total_hopnum = elements[7] # E.g., 100,
        total_hopnum = int(total_hopnum[0:len(total_hopnum)-1]) # E.g., 100
        total_pktnum = elements[10] # E.g., 100,
        total_pktnum = int(total_pktnum[0:len(total_pktnum)-1]) # E.g., 100
        zero_hopnum = elements[17] # E.g., 100,
        zero_hopnum = int(zero_hopnum[0:len(zero_hopnum)-1]) # E.g., 100
        truth_collect_cnt = int(elements[19]) # E.g., 100
        if hostid not in datamap.keys():
            datamap[hostid] = {}
            datamap[hostid]["flownum"] = 0
            datamap[hostid]["save_hopnum"] = 0
            datamap[hostid]["total_hopnum"] = 0
            datamap[hostid]["total_pktnum"] = 0
            datamap[hostid]["zero_hopnum"] = 0
            datamap[hostid]["truth_collect_cnt"] = 0
        datamap[hostid]["flownum"] += 1
        datamap[hostid]["save_hopnum"] += save_hopnum
        datamap[hostid]["total_hopnum"] += total_hopnum
        datamap[hostid]["total_pktnum"] += total_pktnum
        datamap[hostid]["zero_hopnum"] += zero_hopnum
        datamap[hostid]["truth_collect_cnt"] += truth_collect_cnt
fd.close()

total_flownum = 0
save_intpktnum = 0
total_intpktnum = 0
zero_intpktnum = 0
total_truth_cnt = 0
total_collect_cnt = 0
total_truth_collect_cnt = 0
for k,v in datamap.items():
    total_flownum += v["flownum"]
    save_intpktnum += v["save_hopnum"]
    total_intpktnum += v["total_hopnum"]
    total_truth_cnt += v["total_pktnum"]
    total_collect_cnt += v["total_pktnum"]
    zero_intpktnum += v["zero_hopnum"]
    total_truth_collect_cnt += v["truth_collect_cnt"]
completebit = 8
dint_avgbit = float((1+completebit)*(total_intpktnum - save_intpktnum) + 1*save_intpktnum) / float(total_intpktnum)
dintext_avgbit = float((1+completebit)*(total_intpktnum - save_intpktnum) + (1+1)*zero_intpktnum + deltabits[threshold]*(save_intpktnum - zero_intpktnum)) / float(total_intpktnum)
precision = float(total_truth_collect_cnt) / float(total_collect_cnt)
recall = float(total_truth_collect_cnt) / float(total_truth_cnt)
print("flownum: {}, PINT INT-packet num: {} Gpps, DeltaINT INT-packet num: {} Gpps, zero-packet num: {} Gpps, DeltaINT bit cost: {}, precision: {}, recall: {}, DE-DeltaINT bit cost {}"\
        .format(total_flownum, total_intpktnum/0.2/1024/1024/1024, (total_intpktnum-save_intpktnum)/0.2/1024/1024/1024, zero_intpktnum/0.2/1024/1024/1024,
        dint_avgbit, precision, recall, dintext_avgbit))
