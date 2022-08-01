#!/usr/bin/env python3

import os
import sys

if len(sys.argv) != 2:
    print("Usage: python3 accuracy_analysis XXX/accuracy.out")
    exit()

filepath = sys.argv[1]
fd = open(filepath, "r")

avg_res = []
while True:
    line = fd.readline()
    if line == "":
        break
    avg_res.append(float(line))

avg_re = sum(avg_res) / float(len(avg_res))
print("ARE of all states: {}".format(avg_re))

fd.close()
