#-------------------------------------------------------------------------------
# Name:        input_cm
# Purpose:
#
# Author:      wallace
#
# Created:     07/11/2013
# Copyright:   (c) wallace 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from __future__ import print_function
import re
import inspect
import sys
import os
import io

def called_by():
    for frame in reversed(inspect.stack()):
        caller = frame.filename
        base = os.path.basename(caller)
        print(base)
        if base.endswith(".py"):
            if "diff_cf" in base:
                name = "cf"
                break
            if "diff_sh" in base:
                name = "sh"
                break

    return name

import os
import sys
import re

_TS_RE = re.compile(r"^(?P<date>\d{8})-(?P<sec>\d+)$")

def _split_host_ts(filename: str):
    base = filename[:-4] if filename.lower().endswith(".txt") else filename
    if "_" not in base:
        return base, None
    host, ts = base.rsplit("_", 1)
    return host, ts

def _ts_sort_key(filename: str, path_dir: str):
    _, ts = _split_host_ts(filename)
    if ts:
        m = _TS_RE.match(ts)
        if m:
            return (int(m.group("date")), int(m.group("sec")))
    try:
        return (0, int(os.path.getmtime(os.path.join(path_dir, filename))))
    except Exception:
        return (0, 0)

def input_f(force=False, match=False):
    title = ''
    checkname = 'n'
    caller = called_by()
    if caller == 'cf':
        title = ', for Cisco or Juiper configurations only'
        checkname = 'y'
    if caller == 'sh':
        title = ', for show command results only'
        checkname = 'y'

    path = os.path.join("..", "Py_ssh", "outputs")
    paths = os.path.join("..", "Py_ssh", "outputs", "config-check-result")
    os.makedirs(paths, exist_ok=True)

    try:
        files = sorted(f for f in os.listdir(path) if f.endswith("txt"))
    except:
        print('Can not find directory: ' + path)
        sys.exit(0)

    if len(files) < 2:
        print('Need at least two files in directory' + path)
        print('Exsiting!!!')
        sys.exit(0)

    print('\n')
    print('Files available for comparsion' + title + ': \n')
    for number in range(len(files)):
        tempalte1 = '{0:<4} -- {1}'
        print(tempalte1.format(number + 1, files[number]))
    print('\n')

    jobs = []

    # -------------------------
    # -m / match mode
    # -------------------------
    if match:
        groups = {}
        for fn in files:
            host, _ = _split_host_ts(fn)
            groups.setdefault(host, []).append(fn)

        for host, host_files in sorted(groups.items()):
            if len(host_files) < 2:
                continue

            host_files_sorted = sorted(
                host_files,
                key=lambda f: _ts_sort_key(f, path),
                reverse=True
            )
            fn1, fn2 = host_files_sorted[0], host_files_sorted[1]

            file1_n = fn1[:-4] + '.u.txt'
            file2_n = fn2[:-4] + '.u.txt'

            try:
                file1 = open(os.path.join(path, fn1), 'r')
                file2 = open(os.path.join(path, fn2), 'r')
            except:
                print(f'Failed opening original files for host {host}: {fn1} / {fn2}')
                sys.exit(0)

            try:
                file1_u = open(os.path.join(paths, file1_n), 'w')
                file2_u = open(os.path.join(paths, file2_n), 'w')
            except:
                print(f'Failed opening output files for host {host}: {file1_n} / {file2_n}')
                sys.exit(0)

            print(f"[MATCH] {host}:")
            print(f"  NEWEST : {fn1}")
            print(f"  PREV   : {fn2}")
            print()

            jobs.append((file1, file2, file1_u, file2_u, paths))

        if not jobs:
            print("'-m' was used but no host had at least two files to compare.")
            sys.exit(0)

        return jobs

    # -------------------------
    # Interactive mode (but still returns jobs=[one_tuple])
    # -------------------------
    while True:
        xstr = ''
        try:
            xstr = input('Please select one of the files above (by the number):')
            x = int(xstr)
        except:
            if xstr == '':
                sys.exit(0)
            print('Invalid input, please try again')
            continue
        else:
            x -= 1
            if x not in range(len(files)):
                print('Out of range selection, please try again')
                continue
            break

    while True:
        ystr = ''
        try:
            ystr = input('Please select the other one:')
            y = int(ystr)
        except:
            if ystr == '':
                sys.exit(0)
            print('Invalid input, please try again')
            continue
        else:
            y -= 1
            if y not in range(len(files)):
                print('Out of range selection, please try again')
                continue
            if y == x:
                print('Same file selected, please try again')
                continue
            break

    if checkname == 'y' and force is False:
        hx, _ = _split_host_ts(files[x])
        hy, _ = _split_host_ts(files[y])
        if hx != hy:
            print('The two files are not from the same host, can not compare them!')
            sys.exit(0)

    fn1, fn2 = files[x], files[y]
    file1_n = fn1[:-4] + '.u.txt'
    file2_n = fn2[:-4] + '.u.txt'

    try:
        file1 = open(os.path.join(path, fn1), 'r')
        file2 = open(os.path.join(path, fn2), 'r')
    except:
        print('Failed opening one of the original files, exiting')
        sys.exit(0)

    try:
        file1_u = open(os.path.join(paths, file1_n), 'w')
        file2_u = open(os.path.join(paths, file2_n), 'w')
    except:
        print('Failed opening one of the new files, exiting')
        sys.exit(0)

    jobs.append((file1, file2, file1_u, file2_u, paths))
    return jobs