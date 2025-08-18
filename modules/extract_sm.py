#-------------------------------------------------------------------------------
# Name:        extract_cm
# Purpose:     module
#
# Author:      wallace
#
# Created:     01/11/2013
# Copyright:   (c) wallace 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from __future__ import print_function
from modules import compare_sm


# return a list of line indexes that starts the show command
def get_line_i (file_c):

    list = []

    for i in range(len(file_c)):

        if file_c[i][-21:] == ') ---------- result:\n':

            # test good
            #print(file_c[i])

            list.append(i)

    # test good
    #for i in list: print(file_c[i], end='')

    return list


# return a dcitionary of {show_line:show_result,...)
def get_sub(file_z, file_i):

    dict_s = {}

    for index in range(len(file_i)):

        line = int(file_i[index])
        if index == len(file_i) - 1:
            dict_s[file_z[line]] = file_z[line:]

        else:
            line2 = int(file_i[index+1])
            dict_s[file_z[line]] = file_z[line:line2]

    # test good
    """for k in dict_s:
        print('#'*100)
        for line in dict_s[k]:
            print(line, end='')"""

    return dict_s


def extract_f (filex_c, filey_c, filex_u):

    # test good
    #for line in filex_c: print(line)

    filex_sd = {}
    filey_sd = {}

    filex_i = []
    filey_i = []

    # get a list of line indexes that starts the show command
    filex_i = get_line_i(filex_c)
    filey_i = get_line_i(filey_c)

    # get a dcitionary of {show_line:show_result,...)
    filex_sd = get_sub(filex_c, filex_i)
    filey_sd = get_sub(filey_c, filey_i)

    compare_sm.compare_f(filex_sd, filey_sd, filex_u)


    return