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

def input_f(force=False):
   #if sys.version[0] == '2':
   #     input = raw_input

    title = ''
    checkname = 'n'
    caller = called_by()
    if caller == 'cf':
        title = ', for Cisco or Juiper configurations only'
        checkname = 'y'

    if caller == 'sh':
        title = ', for show command results only'
        checkname = 'y'

    # two compare file shuld be at ..\ps\temp\Config
    #path = '..\\temp\\config\\config\\'
    #paths = '..\\temp\\config\\config-check-result\\'
    path = os.path.join("..","Py_ssh","outputs")
    paths = os.path.join("..","Py_ssh","outputs","config-check-result")
    os.makedirs(paths, exist_ok=True)

    try:
        files = sorted(f for f in os.listdir(path) if f.endswith("txt"))
    except:
        print('Can not find directory: '+path)
        sys.exit(0)

    if len(files) < 2:
        print ('Need at least two files in directory' +path)
        print ('Exsiting!!!')
        sys.exit(0)

    print('\n')
    print('Files available for comparsion'+title+': \n')
    for number in list(range(len(files))):
        tempalte1 = '{0:<4} -- {1}'
        print (tempalte1.format(number+1, files[number]))

    print('\n')

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
            x = x - 1
            if x not in range(len(files)):
                print('Out of range selection, please try again')
                continue
            else:
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
            y = y - 1
            if y not in range(len(files)):
                print('Out of range selection, please try again')
                continue
            if y == x:
                print('Same file selected, please try again')
                continue
            else:
                break
    #print(force)
    if checkname == 'y' and force == False:
        #print(files[x].split('_')[0])
        #print(files[y].split('_')[0])
        if files[x].split('_')[0] != files[y].split('_')[0]:
            print('The two files are not from the same host, can not compare them!')
            sys.exit(0)


    #print (files[x], files[y])
    file1_n = files[x][:-4]+'.u.txt'
    file2_n = files[y][:-4]+'.u.txt'

    try:
        file1 = open(os.path.join(path,files[x]), 'r')
        file2 = open(os.path.join(path,files[y]), 'r')

    except:
        print ('Failed opening one of the original files, exiting')
        sys.exit(0)
        
    try:
        file1_u = open(os.path.join(paths,file1_n), 'w')
        file2_u = open(os.path.join(paths,file2_n), 'w')

    except:
        print ('Failed opening one of the new files, exiting')
        sys.exit(0)

    return (file1, file2, file1_u, file2_u, paths)
