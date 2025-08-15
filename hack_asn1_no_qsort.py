#!/usr/bin/env python3

import sys
import re

r_qsort = re.compile('(\s*)([^/]*qsort.*)')

data = []
with open(sys.argv[1], 'r+') as f:
    for line in f:
        m = r_qsort.match(line)
        if m:
            data.append(m.group(1) + "assert(false);")
            data.append(m.group(1) + "//" + m.group(2))
        else:
            data.append(line)

    f.seek(0)
    for d in data:
        f.write(d)
    f.truncate()
