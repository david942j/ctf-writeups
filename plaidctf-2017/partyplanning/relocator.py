#!/usr/bin/env python3

from __future__ import print_function

import subprocess
import sys

filename = 'partyplanning.dump' # objdump
with open(filename, 'r') as f:
    info = f.read().split('\n')

def badline(line):
    return 'call' in line or 'j' in line

def bad(reason):
    print('I', reason)
    exit(0)

size = None
used = set()
destinations = set()
input_addr = int(sys.argv[1], 16)

for i in range(len(info)):
    line = info[i]
    if size == None and line.startswith('  %06x' % input_addr):
        # Found address
        if badline(line): bad('start bad')
        if len(line) < 33: bad('start short')
        for j in range(i+1, len(info)):
            jline = info[j]
            if len(jline) < 33: continue
            nextaddr = int(jline[2:jline.index(':')], 16)
            size = nextaddr - input_addr
            if size >= 5: break
            if badline(jline): bad('middle bad')
            used.add(nextaddr)
        else:
            bad()
    else:
        try:
            curloc = line[38:].split(' ')[1]
            destinations.add(int(curloc, 16))
        except:
            pass

if size != None and not (used & destinations):
    print('V', size)
else:
    bad('Not found')
