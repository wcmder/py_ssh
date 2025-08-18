#-------------------------------------------------------------------------------
# Name:        diff_cf
# Purpose:     main
#
# Author:      wallace
#
# Created:     01/11/2013
# Copyright:   (c) wallace 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------

from __future__ import print_function
import os
import sys
from modules import extract_cm
from modules.input_cm import *
import argparse

def main():
    parser = argparse.ArgumentParser(description="DIFF FOR CONFIG")
    parser.add_argument("-f", "--force", action="store_true", help="Force to ignore hostname check")
    args = parser.parse_args()    

    inputfiles = input_f(args.force)
    file1 = inputfiles[0]
    file2 = inputfiles[1]
    file1_u = inputfiles[2]
    file2_u = inputfiles[3]
    paths = inputfiles[4]

    # remove all the line starts with ! and empty lines
    filex_c = [line.rstrip()+"\n" for line in file1 if not line.startswith('!') and not line == '\n']
    filey_c = [line.rstrip()+"\n" for line in file2 if not line.startswith('!') and not line == '\n']

    print('Comparing...')
    extract_cm.extract_f(filex_c, filey_c, file1_u)

    if file1_u.tell() == 0:
        file1_u.write('NO DIFFERENCE FOUND')

    file1_u.close()

    print('Comparing...')
    extract_cm.extract_f(filey_c, filex_c, file2_u)
    file1.close()
    file2.close()

    if file2_u.tell() == 0:
        file2_u.write('NO DIFFERENCE FOUND')

    file2_u.close()
    
    # windows only
    #if 'win' in sys.platform:
    #    os.system('start explorer.exe '+paths)

    print('Finished')

if __name__ == '__main__':
    main()
