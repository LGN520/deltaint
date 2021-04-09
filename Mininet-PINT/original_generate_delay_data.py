import sys
import os
file_name=sys.argv[1]

os.system("mkdir -p experiments/delays/")

# Format of each line: time, "n:"node, intf:qidx, qlen, event, "ecn:"ecn, sip, dip, sport, dport, l3port, seq, ts, pg, pktsize(MTU) [payload]
f=open(file_name,"r")
data={}
valid_linenum = 0
max_linenum = 1000*1000
for line in f:
    elements = line.strip().split(" ")
    time = int(elements[0])
    event = elements[4]
    if event == "Enqu":
        pkt = line.strip().split("Enqu")[1] # including flow ID, deq number, device ID
        data[pkt]=[time, -1]
        valid_linenum += 1
    if event == "Dequ":
        pkt = line.strip().split("Dequ")[1]
        if pkt not in data:
            continue
        data[pkt][1]=time
        valid_linenum += 1
    if valid_linenum >=max_linenum:
        break
print("Valid line number: {}".format(valid_linenum))
f.close()

all=[]
pint_4=[]
pint_8=[]
valid_latencynum = 0
for key,value in data.items():
    if value[1] == -1: # Invalid condition
        continue
    all.append(abs(value[1] - value[0]))
    valid_latencynum += 1
print("Valid latency number: {}".format(valid_latencynum))

fw=open("experiments/delays/processed_data","w")
for item in all:
    fw.write(str(item)+"\n")
fw.close()
