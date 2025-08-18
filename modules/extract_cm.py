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
from modules import compare_cm

def extract_f (filex_c, filey_c, filex_u):

    # test good
    #for line in filex_c: print(line)

    filex_s = []
    filey_s = []
    flag1 = ''

    for i in range(len(filex_c)):

        # case - global config
        if not filex_c[i].startswith(' '):
            
            # global line
            if i+1 < len(filex_c) and not filex_c[i+1].startswith(' '):
                filex_s.append(filex_c[i])
                flag1 = 'g'
                continue
            
            #
            else:
                # if the end, add it
                if i+1 == len(filex_c):
                    filex_s.append(filex_c[i])

                # test good
                #for line in filex_s: print(line, end='')

                # could be accumulated global lines
                # could just be one line
                # send accumulated global line up to i from x and the whole file from y
                compare_cm.compare_f(filex_s, filey_c, flag1, filex_u)
                flag1 = ''
                filex_s = []
                
                # append the parentline for next case
                filex_s.append(filex_c[i])
                continue

        # case - sub level config
        # i line start with space
        else:
            # i line is the 2nd line in sube level
            # parent line is i - 1, save to filex_s above
            #print(filex_c[i])
            filex_s.append(filex_c[i])
            flag1 = 's'

            # test good
            #print(filex_c[i], end='')

            # reach the end of sub in x
            if i+1 == len(filex_c) or not filex_c[i+1].startswith(' '):

                #print('test '+filex_s[0])
                if filex_s[0] in filey_c:

                    # test good
                    #print('found '+filex_s[0])

                    # find the same sub in y
                    s_index = filey_c.index(filex_s[0])
                    #print(filey_c[s_index])
                    filey_s.append(filey_c[s_index])
                    n_index = s_index + 1
                    
                    # find the start and end at filey_c and save to filey_s
                    while n_index < len(filey_c) and filey_c[n_index].startswith(' '):
                        filey_s.append(filey_c[n_index])
                        n_index = n_index + 1

                    # test good
                    #for line in filex_s: print(line, end='')
                    #for line in filey_s: print(line, end='')

                    # send sub-level from x, and sub-level from y
                    compare_cm.compare_f(filex_s, filey_s, flag1, filex_u)
                    flag1 = ''
                    filex_s = []
                    filey_s = []
                    continue

                # no sub level found in the other file
                else:
                    filey_s = None

                    # test good
                    #for line in filex_s: print(line, end='')

                    compare_cm.compare_f(filex_s, filey_s, flag1, filex_u)
                    flag1 = ''
                    filex_s = []
                    filey_s = []
                    continue

            else:
                continue
    return