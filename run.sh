#!/bin/bash

# active virtual env
source /Users/wder/Documents/projects/Py_ssh/bin/activate

/Users/wder/Documents/projects/Py_ssh/bin/python3 /Users/wder/Documents/projects/Py_ssh/py_ssh.py -a

# schedule with cron - min/hr/day/month/year script >> error stderr>&stdout
#   crontab -e
#   52 15 * * * /Users/wder/Documents/projects/Py_ssh/run.sh >> /Users/wder/Documents/projects/Py_ssh/outputs/cron.log 2>&1
#   
# check
#   crontab -l

