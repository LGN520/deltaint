import sys
import os
file_name=sys.argv[1]

os.system("mkdir -p experiments/delays/")

# Format of each line: time, "n:"node, intf:qidx, qlen, event, "ecn:"ecn, sip, dip, sport, dport, l3port, seq, ts, pg, pktsize(MTU) [payload]
f=open(file_name,"r")
data={} # {flow, {seq, [(Enqu, Dequ, node)*hopnum]}}
datalist=[] # [(flow, seq, node, hopidx, latency)]
valid_linenum = 0
max_linenum = 1000*1000
for line in f:
    elements = line.strip().split(" ")
    time = int(elements[0]) # Unit: ns
    node = elements[1][2:] # Remove "n:"
    #dev = int(elements[1].split(":")[1])
    #dev = dev%5 # 5-hop Fat Tree Topology
    event = elements[4]
    sip = elements[6]
    dip = elements[7]
    sport = elements[8]
    dport = elements[9]
    seq = elements[11]
    #pkt = "{}-{}-{}-{}-{}".format(sip, dip, sport, dport, seq)
    #flow = "{}-{}".format(sip, dip)
    flow = (int(sip, 16) << 32) | int(dip, 16)
    if event == "Enqu":
        if flow not in data:
            data[flow] = {}
            data[flow][seq] = []
            data[flow][seq].append([time, -1, node])
        elif seq not in data[flow]:
            data[flow][seq] = []
            data[flow][seq].append([time, -1, node])
        else:
            data[flow][seq].append([time, -1, node])
        valid_linenum += 1
    elif event == "Dequ":
        if flow not in data or seq not in data[flow]:
            continue
        for i in range(len(data[flow][seq])):
            if data[flow][seq][i][2] == node and data[flow][seq][i][1] == -1:
                data[flow][seq][i][1] = time
                if i >= 0 and i < 5: # flow, seq, node, hopidx, latency
                    datalist.append((flow, seq, node, i, abs(data[flow][seq][i][1] - data[flow][seq][i][0])))
                valid_linenum += 1
                break
    else:
        continue
    if valid_linenum >=max_linenum:
        break
print("Valid line number: {}".format(valid_linenum))
f.close()

fw=open("experiments/delays/{}".format(sys.argv[2]),"w")
valid_latencynum = 0
for _ in range(1): # Run 20 times for stability
    for i in range(len(datalist)):
        # flow, seq, node, hopidx, latency, hopnum
        flow = datalist[i][0]
        seq = datalist[i][1]
        hopnum = len(data[flow][seq])
        if hopnum > 5:
            hopnum = 5
        fw.write("{} {} {} {} {} {}\n".format(flow, seq, datalist[i][2], datalist[i][3], datalist[i][4], hopnum))
        valid_latencynum += 1
print("Valid latency number: {}".format(valid_latencynum))
fw.close()
