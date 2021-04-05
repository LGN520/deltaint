import sys

if len(sys.argv) != 2:
    print("Example: python3 plothelper.py simulation/mix/DINT_cur_alwaysdelta_5/DINT_fb.out")
    exit(-1)

filepath = sys.argv[1]
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
        if hostid not in datamap.keys():
            datamap[hostid] = {}
            datamap[hostid]["flownum"] = 0
            datamap[hostid]["save_hopnum"] = 0
            datamap[hostid]["total_hopnum"] = 0
        datamap[hostid]["flownum"] += 1
        datamap[hostid]["save_hopnum"] = save_hopnum
        datamap[hostid]["total_hopnum"] = total_hopnum
fd.close()

total_flownum = 0
save_intpktnum = 0
total_intpktnum = 0
for k,v in datamap.items():
    total_flownum += v["flownum"]
    save_intpktnum += v["save_hopnum"]
    total_intpktnum += v["total_hopnum"]
print("flownum: {}, PINT INT-packet num: {} Gpps, DeltaINT INT-packet num: {} Gpps"\
        .format(total_flownum, total_intpktnum/0.2/1024/1024/1024, (total_intpktnum-save_intpktnum)/0.2/1024/1024/1024))
