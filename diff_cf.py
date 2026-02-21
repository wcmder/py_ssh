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
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="DIFF FOR CONFIG")
    parser.add_argument("-f", "--force", action="store_true", help="Force to ignore hostname check")
    parser.add_argument("-m", "--match", action="store_true", help="Force to match all files, skip prompt")
    args = parser.parse_args()

    jobs = input_f(match=args.match, force=args.force)
    print('[INFO] Comparing...\n')
    for file1, file2, file1_u, file2_u, paths in jobs:
        # run your compare logic here per host

        #inputfiles = input_f(args.force)
        #file1 = inputfiles[0]
        #file2 = inputfiles[1]
        #file1_u = inputfiles[2]
        #file2_u = inputfiles[3]
        #paths = inputfiles[4]

        # remove all the line starts with ! and empty lines
        filex_c = [line.rstrip() + "\n" for line in file1 if not line.lstrip().startswith(('!', 'Current configuration')) and line.strip() != ""]
        filey_c = [line.rstrip() + "\n" for line in file2 if not line.lstrip().startswith(('!', 'Current configuration')) and line.strip() != ""]

        extract_cm.extract_f(filex_c, filey_c, file1_u)

        if file1_u.tell() == 0:
            #file1_u.write('NO DIFFERENCE FOUND')
            print(f"[INFO]  NO diff --> {Path(file1.name).name} from {Path(file2.name).name}")
            file1_u.close()
            os.remove(file1_u.name)

        else:
            print(f"[INFO] YES diff --> {Path(file1.name).name} from {Path(file2.name).name}")
            file1_u.close()
        
        extract_cm.extract_f(filey_c, filex_c, file2_u)

        if file2_u.tell() == 0:
            #file2_u.write('NO DIFFERENCE FOUND')
            print(f"[INFO]  NO diff --> {Path(file2.name).name} from {Path(file1.name).name}")
            file2_u.close()
            os.remove(file2_u.name)

        else:
            print(f"[INFO] YES diff --> {Path(file2.name).name} from {Path(file1.name).name}")
            file2_u.close()
        
        file1.close()
        file2.close()

        # windows only
        #if 'win' in sys.platform:
        #    os.system('start explorer.exe '+paths)

    print('\nDONE\n')

if __name__ == '__main__':
    main()
