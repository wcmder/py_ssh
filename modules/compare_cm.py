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

# take only one line and return the parentline above
# figure out the parentline within the sub level, such as sub within sub
# check each line above index but counting the length to find out the parentlines above it
# return the directory with 
def find_parentlines_f(portion, index):
    parentlines = {}
    line = portion[index]

    # test good
    #for line in portion: print(line, end='')

    # count how many spaces at line i
    zeros_t = len(line) - len(line.lstrip())
    
    # step from i backward, i is biggest
    for i in range(index, -1, -1):
        line_n = portion[i-1]
        
        # count how many space at line i - 1
        zeros_n = len(line_n) - len(line_n.lstrip())

        # if above line has less spaces, found the parentline
        if zeros_n < zeros_t:
            # save 
            parentlines.update({i-1:line_n})
            zeros_t = zeros_n

        if i == 1:
            break

    # test
    #for key in parentlines: print(key, parentlines[key], end='')

    return parentlines

# takes sub-config, either global level or one sub-level
def compare_f (portionx, portiony, mode, file_u):

    portionz = []
    portiond = {}

    # at the end of file 
    if portiony == None:

        # test good
        #for line in portionx: print(line, end='')

        portionx.append('!\n')
        file_u.writelines(portionx)

    # at global level, x is sub, y is whole
    elif mode == 'g':

        for linex in portionx:

            # test good
            #print(linex, end='')

            #for liney in portiony:
            #    if linex == liney:
            #        break

            if linex in portiony:
                continue

            else:

                # test good
                #print(linex, end='')

                portionz.append(linex)

        if not portionz == []:
            portionz.append('!\n')

        file_u.writelines(portionz)

    # at sub level, x is sub and y is sub
    elif mode == 's':

        # test good
        #for line in portiony: print(line, end='')
        #print('!\n')

        for m in range(1, len(portionx)):
            parentlinesxd = {}
            linex = portionx[m]
            parentlinesxd = find_parentlines_f(portionx, m)

            # test good
            #for key in parentlinesxd: print(key, parentlinesxd[key], end='')
            #print('!\n')
            #print(linex, portionx.index(linex))

            # step throught y
            # if a match found, check if they came form same parentline
            for n in range(1, len(portiony)):
                parentlinesyd = {}
                liney = portiony[n]

                # found a match line
                if linex == liney:
                    # find parentline
                    parentlinesyd = find_parentlines_f(portiony, n)

                    # test good
                    #for key in parentlinesyd: print(key, parentlinesyd[key], end='')
                    #print('!\n')

                    parentlinesx = [parentlinesxd[kx] for kx in parentlinesxd]
                    parentlinesy = [parentlinesyd[ky] for ky in parentlinesyd]

                    # if the same line has the same parentline, break out of loop
                    if parentlinesx == parentlinesy:
                        break

                    else:
                        continue
            
            # at the end, the m line at portionx has no match
            # save the parentline, and the m line
            else:
        
                portiond.update(parentlinesxd)
                portiond.update({m:portionx[m]})

        keys = [key for key in portiond]
        keys.sort()

        # test good
        #for k in keys: print(k, portiond[k])

        for k in keys:
            portionz.append(portiond[k])

        if len(portionz) != 0:
            portionz.append ('!\n')

        file_u.writelines(portionz)

    return





