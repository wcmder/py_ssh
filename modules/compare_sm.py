#-------------------------------------------------------------------------------
# Name:        compare_cm
# Purpose:     module
#
# Author:      wallace
#
# Created:     01/11/2013
# Copyright:   (c) wallace 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from __future__ import print_function
import re
import sys

def remove_time(line, key):

    if re.match('.*Issued Command: \( sh.* cdp', key):
        line_n = re.sub('(.{33}\s\s)\d\d?\d?', '\g<1>TIME_REMOVED', line)
        line_n = re.sub(' ', '', line_n)

    else:
        # match for ' 1w2d' or ' 1d02h' or '00:00:01' or ' 1y2w'
        line_n = re.sub('\s\d\d?w\dd|\s\dd\d\d?h|\d\d:\d\d:\d\d|\s\dy\d\d?w',
                        'TIME_REMOVED', line)

        # test good
        #print(line_n)

        line_n = re.sub(' ', '', line_n)

    return line_n

def normalized_ospf_route(listz):

    for i in range(len(listz)):

        if re.match('\s\s\s+\[\d+/\d+\]', listz[i]):
            #print(listz[i], end='')

            if re.match('O.* \d+\.\d+\.\d+.\d+/\d+\s*$', listz[i-1]):
                #print(listz[i-1], end='')
                listz[i-1] = listz[i-1][:-2] + listz[i]
                listz[i] = ' '
                #print(listz[i-1], end='')


def normalized_bgp_nei(listz):

    for line in listz:
        pass

#
def compare_f (dx, dy, file_u):

    result = []

    # test
    """for k in dx:
        print('#'*100)
        for line in dx[k]:
            print(line, end='')"""

    for key in dx:

        # ignor the show command if not found in other file
        try:
            dy[key]
        except:
            continue

        result.append(key)
        result.append('!\n')
        found = 'n'

        # normalized "show ip router ospf"
        if re.match('Host name:.*sh.*ip route ospf', key):
            normalized_ospf_route(dx[key])
            normalized_ospf_route(dy[key])

        # normalized "show bgp summ"
        # pending
        """if re.match('Host name:.*sh.*bgp sum', key):
            normalized_bgp_nei(dx[key])
            normalized_bgp_nei(dy[key])"""

        for linex in dx[key]:

            # test good
            #print(linex, end='')

            # remove times and spances in the lines
            linex_n = remove_time(linex, key)

            # test good
            """if re.findall('(\s\dw\dd)|(\s\dd\d\dh)|(\d\d:\d\d:\d\d)', linex):
                print(linex)
                print(linex_n)"""

            for liney in dy[key]:

                # remove times and spances in the lines
                liney_n = remove_time(liney, key)

                # comare line after remmoved the times and spaces
                if linex_n == liney_n:
                    break

            else:
                found = 'y'
                result.append(linex)

        if found != 'y':
            result.append('SAME\n\n\n\n')

        else:
            result.append('\n\n\n')

    file_u.writelines(result)

    return





