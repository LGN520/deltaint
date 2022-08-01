import sys

if len(sys.argv) != 2:
    print("Example: python3 plothelper.py ./final_results/59/avg/PINT8")

filepath = sys.argv[1]
fd = open(filepath, "r")
lines = fd.readlines()
fd.close()

rs = ""
for i in range(len(lines)):
    line = lines[i].strip()
    _, v = line.split(",")
    rs += v
    if i != (len(lines)-1):
        rs += ","
print(rs)
