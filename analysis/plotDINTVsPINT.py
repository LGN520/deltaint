#!/usr/bin/python
import subprocess
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
from matplotlib import ticker
from matplotlib.pyplot import cm 
import numpy as np
import pylab
import random
from math import exp,ceil,log
import sys
import os.path
from os import path
import numpy as np
import argparse

parser = argparse.ArgumentParser(description='')
parser.add_argument('-d', dest="dataset", action='store', default='fb', help="Dataset like fb or wb")
args = parser.parse_args()

#matplotlib.rcParams['ps.useafm'] = True
#matplotlib.rcParams['pdf.use14corefonts'] = True
#matplotlib.rcParams['text.usetex'] = True
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
    
fig, ax = plt.subplots(figsize=(10,5))    

plt.grid()
plt.gcf().subplots_adjust(bottom=0.15)

datfile = 'fct_{}50_dint_mi0_log1.05_vs_pint.dat'.format(args.dataset)

PINT_50 = [float(line.split()[2]) for line in open(datfile).readlines()[0:]]     # web search
PINT_95 = [float(line.split()[3]) for line in open(datfile).readlines()[0:]]     # web search
PINT_99 = [float(line.split()[4]) for line in open(datfile).readlines()[0:]]     # web search
DINT_50 = [float(line.split()[5]) for line in open(datfile).readlines()[0:]]    # web search
DINT_95 = [float(line.split()[6]) for line in open(datfile).readlines()[0:]]    # web search
DINT_99 = [float(line.split()[7]) for line in open(datfile).readlines()[0:]]    # web search
HPCC_50 = [float(line.split()[8]) for line in open(datfile).readlines()[0:]]    # web search
HPCC_95 = [float(line.split()[9]) for line in open(datfile).readlines()[0:]]    # web search
HPCC_99 = [float(line.split()[10]) for line in open(datfile).readlines()[0:]]    # web search

x_axis = [int(line.split()[1]) for line in open(datfile).readlines()[0:]] # wb flow sizes

plt.plot(np.linspace(0, 10, num=20),HPCC_95, color='black', linestyle='-.', label='HPCC',linewidth=4.0)
plt.plot(np.linspace(0, 10, num=20),PINT_95, color='red', linestyle='-', label='HPCC(PINT)',linewidth=4.0)
plt.plot(np.linspace(0, 10, num=20),DINT_95, color='blue', linestyle='--', label='HPCC(DINT)',linewidth=4.0)
plt.ylim([1,11])
ax.set_xticks(range(1,11))
ax.set_xticklabels([str(x) if x < 1000 else str(int(x/1000. + .5)) + 'K' if x < 1000.**2 else str(int(x/1000.**2 + .5)) + 'M' for x in x_axis[1::2]])


plt.legend(loc='upper left',prop={'size':24},ncol=1)
plt.tick_params(axis='both', which='major', labelsize=18)
plt.tick_params(axis='y', which='major', labelsize=28)
plt.ylabel(r'Slowdown', fontsize=28)    
plt.xlabel('Flow Size [Bytes]', fontsize=28)
#plt.xlim([0, maxPkts])
plt.tight_layout()
plt.savefig('{}_95p.pdf'.format(args.dataset))
plt.savefig('{}_95p.png'.format(args.dataset))

