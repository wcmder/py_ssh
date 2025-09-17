#-------------------------------------------------------------------------------
# Name:        diff_sh
# Purpose:     main
#
# Author:      wallace
#
# Created:     07/19/2022
# Copyright:   (c) wallace 2022
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import os
import sys
import re
import glob


# get a set all file names under the given path
def get_hostname_f(path):

    try:
        files = os.listdir(path)
    except:
        print('Can not find directory: '+path)
        sys.exit(0)

    if len(files) < 2:
        print ('Need at least two files in directory' +path)
        print ('Exsiting!!!')
        sys.exit(0)

    print('\n')

    hostname = set()
    for n in list(range(len(files))):
        if 'status.txt' in files[n]:
            hostname.add((re.split('-\w{3,4}-status.txt', files[n])[0]))
    
    print("found these host file -")
    print(hostname)
    return hostname


# read the files and return the open file objects
def read_f(pre, post):
    try:
        pref = open(pre, 'r')
    except:
        print ('can not find: ', end="")
        print (pre)
        return 0
    try:
        postf = open(post, 'r')
    except:
        print ('can not find: ', end="")
        print (post)
        return 0
    else:
        return (pref, postf)


# take the two files of list and return them as dict in {key1:lines, key2,lines, ...}
def extract_f(pref, postf):
    pref_header_i = get_header_f(pref)
    postf_header_i = get_header_f(postf)
    pref_d = get_dict_f(pref, pref_header_i)
    postf_d = get_dict_f(postf, postf_header_i)

    return (pref_d, postf_d)




# return a list of line indexes that starts with 20 of !
def get_header_f(pfile):

    marker = '#'*10
    header_i = []

    for i in range(len(pfile)):

        if  marker in pfile[i]:
            #print(i)
            header_i.append(i)
            #break
    #print(header_i)
    return header_i



# return a dcitionary, header line would be the key, header line -1 : next header line -1 would be the value 
def get_dict_f(pfile, header_i):

    dict_s = {}

    for i in range(len(header_i)):

        # last 
        if i ==  len(header_i)-1:
            #print (pfile[ int(header_i[i])+1: ])
            dict_s[ pfile[int(header_i[i])] ] = pfile[ int(header_i[i])+1: ]
        else:
            #print (pfile[int(header_i[i])])
            dict_s[ pfile[int(header_i[i])] ] = pfile[ int(header_i[i])+1:int(header_i[i+1])-1 ]

    return dict_s



# compare 
def compare_f(d1, d2):
    keys = [k for k,v in d1.items()]
    diff = []
    #print(keys)

    # k is the the orignal line, also the key in dict

    for k in keys:
        #print(k)
        #print(type(d1[k]))
        #print(type(d2[k]))
        tdiff = []

        # only check those with more than 2 lines
        # pre to post
        if len(d1[k])>2:
            tdiff.append(k)
            tdiff = tdiff + (output_check_f(k, d1[k], d2[k]))

        if (len(tdiff))>1:
            tdiff.insert(1, '!   BEFORE')
            #print (tdiff)
            diff.extend(tdiff)
            diff.append('\n')
        
        tdiff = []

        # only check those with more than 2 lines
        # post to pre
        if len(d2[k])>2:
            tdiff= tdiff + (output_check_f(k, d2[k], d1[k]))
            #print(tdiff)
        if (len(tdiff))>=1:
            if k not in diff:
                tdiff.insert(0, k)
                tdiff.insert(1, '!   AFTER')
            else:
                tdiff.insert(0, '!   AFTER')
            #print (tdiff)
            diff.extend(tdiff)
            diff.append('\n\n\n')
        

    #for d in diff:
    #    print(d)

    return diff


    
# this take only one element of the dict
# k is the dict k, p1 or p2 is the value of dict
def output_check_f(key, p1, p2):
    #print(key)
    rlist = []

    if "cisco interface status" in key.lower():
        rlist = rlist+(compare_int_stat_cisco_f(p1, p2))
    
    elif "arp table" in key.lower():
        rlist = rlist+(compare_arp_tbl_f(p1, p2))

    elif "mac table" in key.lower():
        rlist = rlist+(compare_mac_tbl_f(p1, p2))

    elif "access session" in key.lower():
        rlist = rlist+(compare_access_ses_f(p1, p2))

    elif "bgp summary" in key.lower():
        rlist = rlist+(compare_bgp_stat_f(p1, p2))
    
    elif "lisp status" in key.lower():
        rlist = rlist+(compare_lisp_stat_f(p1, p2))

    elif "arista interface status" in key.lower():
        rlist = rlist+(compare_int_stat_arista_f(p1, p2))

    elif "interface description" in key.lower():
        rlist = rlist+(compare_int_des_f(p1, p2))

    elif "portchannel" in key.lower():
        rlist = rlist+(compare_portchannel_f(p1, p2))
        
    elif "isdn status" in key.lower():
        rlist = rlist+(compare_isdn_f(p1, p2))

    elif "bridge domain" in key.lower():
        rlist = rlist+(compare_bdi_f(p1, p2))

    elif "sip tls" in key.lower():
        rlist = rlist+(compare_sip_tls_f(p1, p2))
    
    elif "ospf database" in key.lower():
        rlist = rlist+(compare_ospf_db_f(p1, p2))

    elif "ip route" in key.lower():
        rlist = rlist+(compare_ip_route_f(p1, p2))   

    return rlist


def compare_ip_route_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'^(\s+){0,1}(\w{1,2}\s+){1,2}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{0,2}){0,1}.*', linex, re.IGNORECASE)
        if x:
            if x.group(4) is not None:
                xdict[x.group(3)+x.group(4)] = x.group(0)
            else:
                xdict[x.group(3)] = x.group(0)

    for liney in p2:
        y = re.search(r'^(\s+){0,1}(\w{1,2}\s+){1,2}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{0,2}){0,1}.*', liney, re.IGNORECASE)
        if y:
            if y.group(4) is not None:
                ydict[y.group(3)+y.group(4)] = y.group(0)
            else:
                ydict[y.group(3)] = y.group(0)

    
    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_ospf_db_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', linex, re.IGNORECASE)
        if x:
            xdict[x.group(1)] = x.group(0)

    for liney in p2:
        y = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', liney, re.IGNORECASE)
        if y:
            ydict[y.group(1)] = y.group(0)

    
    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_arp_tbl_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'(internet\s+){0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(\w{4}\.\w{4}\.\w{4})\s+.*', linex, re.IGNORECASE)
        if x:
            xdict[x.group(3)] = x.group(0)

    for liney in p2:
        y = re.search(r'(internet\s+){0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(\w{4}\.\w{4}\.\w{4})\s+.*', liney, re.IGNORECASE)
        if y:
            ydict[y.group(3)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_mac_tbl_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'(\s){0,10}(\w+)\s+(\w{4}\.\w{4}\.\w{4}\s+((DYNAMIC)|(STATIC)))\s+.*', linex, re.IGNORECASE)
        if x:
            xdict[x.group(2)+x.group(3)] = x.group(0)
            #print(x.group(2))

    for liney in p2:
        y = re.search(r'(\s){0,10}(\w+)\s+(\w{4}\.\w{4}\.\w{4}\s+((DYNAMIC)|(STATIC)))\s+.*', liney, re.IGNORECASE)
        if y:
            ydict[y.group(2)+y.group(3)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_access_ses_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'(.+)\s+(\w{4}\.\w{4}\.\w{4})\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)', linex, re.IGNORECASE)
        if x:
            xdict[x.group(2)+x.group(5)] = x.group(0)

    for liney in p2:
        y = re.search(r'(.+)\s+(\w{4}\.\w{4}\.\w{4})\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)', liney, re.IGNORECASE)
        if y:
            ydict[y.group(2)+y.group(5)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist


def compare_int_stat_cisco_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'(.+)\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(unassigned))\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)', linex, re.IGNORECASE)
        if x:
            xdict[x.group(1)+x.group(2)+x.group(7)+x.group(8)] = x.group(0)

    for liney in p2:
        y = re.search(r'(.+)\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(unassigned))\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)', liney, re.IGNORECASE)
        if y:
            ydict[y.group(1)+y.group(2)+y.group(7)+y.group(8)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_int_stat_arista_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'((\w|/)+)\s+.*((connected)|(notconnect)|(disabled)).*', linex, re.IGNORECASE)
        if x:
            xdict[x.group(1)+x.group(2)] = x.group(0)
            #print(x.group(2))

    for liney in p2:
        y = re.search(r'((\w|/)+)\s+.*((connected)|(notconnect)|(disabled)).*', liney, re.IGNORECASE)
        if y:
            ydict[y.group(1)+y.group(2)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_int_des_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'((\w|/)+)\s+(\w+)\s+(\w+)\s+.*', linex, re.IGNORECASE)
        if x:
            xdict[x.group(1)+x.group(3)+x.group(4)] = x.group(0)


    for liney in p2:
        y = re.search(r'((\w|/)+)\s+(\w+)\s+(\w+)\s+.*', liney, re.IGNORECASE)
        if y:
            ydict[y.group(1)+y.group(3)+y.group(4)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_portchannel_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        x = re.search(r'(\d+)\s+((\w|\(|\)|/)+)\s+\w+\s+((\w|\(|\)|/)+)\s+((\w|\(|\)|/)+)', linex, re.IGNORECASE)
        if x:
            xdict[x.group(2)+x.group(4)+x.group(6)] = x.group(0)
            #print(x.group(0))
            #print(x.group(4))
            #print(x.group(6))


    for liney in p2:
        y = re.search(r'(\d+)\s+((\w|\(|\)|/)+)\s+\w+\s+((\w|\(|\)|/)+)\s+((\w|\(|\)|/)+)', liney, re.IGNORECASE)
        if y:
            ydict[y.group(2)+y.group(4)+y.group(6)] = y.group(0)

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_bgp_stat_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        #print(linex)
        x = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*\s+(\w+)', linex, re.IGNORECASE)
        if x:
            xdict[x.group(1)+"-"+x.group(2)] = x.group(0)
            #print(x.group(1)+"-"+x.group(2))

    for liney in p2:
        #print(liney)
        y = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*\s+(\w+)', liney, re.IGNORECASE)
        if y:
            ydict[y.group(1)+'-'+y.group(2)] = y.group(0)
            #print(y.group(1)+'-'+y.group(2))

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_lisp_stat_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        #print(linex)
        x = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:\d+\s+(\w+)\s+.*', linex, re.IGNORECASE)
        if x:
            xdict[x.group(1)+"-"+x.group(2)] = x.group(0)
            #print(x.group(1)+x.group(2))
            #print(x.group(0))

    for liney in p2:
        #print(liney)
        y = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:\d+\s+(\w+)\s+.*', liney, re.IGNORECASE)
        if y:
            ydict[y.group(1)+'-'+y.group(2)] = y.group(0)
            #print(y.group(1)+'-'+y.group(2))

    xlist = set(xdict.keys())
    ylist = set(ydict.keys())

    for x in xlist-ylist:
        rlist.append(xdict[x])

    return rlist

def compare_isdn_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    for linex in p1:
        #print(linex)
        x = re.search(r'(isdn serial.*)', linex, re.IGNORECASE)
        if x:
            x1 = x
            continue
        x2 = re.search(r'(tei =.*)', linex, re.IGNORECASE)
    
        if x2:
            xdict[x1.group(1)] = x2.group(1)
            #print(x.group(1)+x.group(2))

    for liney in p2:
        
        y = re.search(r'(isdn serial.*)', liney, re.IGNORECASE)
        if y:
            y1 = y
            #print(y1.group(1))
            continue
        y2 = re.search(r'(tei =.*)', liney, re.IGNORECASE)
    
        if y2:
            ydict[y1.group(1)] = y2.group(1)

    
    xlist = [k for k,v in xdict.items()]
    #print(len(xlist))
    #ylist = [k for k,v in ydict.items()]
    #print(len(ylist))

    for x in xlist:
        #print('all '+x)
        if set(xdict[x]) != set(ydict[x]):
            rlist.append(x+' '+xdict[x])
            #print(x)

    return rlist



def compare_bdi_f (p1, p2):
    rlist = []
    xdict = {}
    ydict = {}
    
    i = 0
    while i < len(p1):
        #print("-------"+str(i))
        x = re.search(r'(bridge-domain \d+)\s.*', p1[i], re.IGNORECASE)
        if x:
            k = 1
            #print(x.group(1))
            xdict[x.group(1)]=""
            
            for k in range(1000):
                n = i+k
                x1 = re.search(r'.*(\w\w\w\w\.\w\w\w\w\.\w\w\w\w).*', p1[n], re.IGNORECASE)
                #print(p1[n])
                if x1:
                    #print(x1.group(1))
                    xdict[x.group(1)] = xdict[x.group(1)] + ', ' + x1.group(1)
                elif p1[n] == '' or p1[n] == '#END' or p1[n][-1] == "#":
                    #print("--------------------")
                    i = n
                    #print(xdict)
                    break
                
        else:
            i = i+1

    j = 0
    while j < len(p2):
        #print("-------"+str(j))
        #print(linex)
        x = re.search(r'(bridge-domain \d+)\s.*', p2[j], re.IGNORECASE)
        if x:
            k = 1
            #print(x.group(1))
            ydict[x.group(1)]=""
            
            for k in range(1000):
                n = j+k
                x1 = re.search(r'.*(\w\w\w\w\.\w\w\w\w\.\w\w\w\w).*', p2[n], re.IGNORECASE)
                #print(p2[n])
                if x1:
                    #print(x1.group(1))
                    ydict[x.group(1)] = ydict[x.group(1)] + ', ' + x1.group(1)
                    
                elif p2[n] == '' or p2[n] == '#END' or p2[n][-1] == "#":
                    #print("--------------------")
                    j = n
                    #print(ydict)
                    break
                
        else:
            j = j+1
    
 
    xlist = [k for k,v in xdict.items()]
    #print(len(xlist))
    #ylist = [k for k,v in ydict.items()]
    #print(len(ylist))

    for x in xlist:
        #print('all '+x)
        if set(xdict[x]) != set(ydict[x]):
            rlist.append(x+xdict[x])
            #print(x)    
    

    return rlist


def compare_sip_tls_f (p1, p2):
    rlist = []
    xlist = []
    ylist = []
    
    for linex in p1:
        #print(linex)
        x = re.search(r'(Remote-Agent\:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', linex, re.IGNORECASE)
        if x:
            xlist.append(x.group(0))
            #print(x.group(0))

    for liney in p2:
        #print(liney)
        y = re.search(r'(Remote-Agent\:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', liney, re.IGNORECASE)
        if y:
            ylist.append(y.group(0))
            #print(y.group(0))

    for x in xlist:
        #print('all '+x)
        if x not in ylist:
            rlist.append(x)
            #print(x)

    return rlist



def go_compare_f (fpath, dfpath, hostnames):

    # delete current diff file
    os.makedirs(dfpath, exist_ok = True)
    dfiles = glob.glob(os.path.join(dfpath,'*-DIFF.txt'))
    for eachdfile in dfiles:
        try:
            os.remove(eachdfile)
            #print(eachdfile)
        except:
            print("No such file anymore: "+eachdfile)


    for each_name in hostnames:

        pref_name = os.path.join(fpath,each_name+"-pre-status.txt",)
        postf_name = os.path.join(fpath,each_name+"-post-status.txt")
        pfiles = read_f(pref_name, postf_name)
        #print(pfiles)
        
        if pfiles:
            # r1 and r2 are the whole file now in dict 
            r1,r2 = extract_f(pfiles[0].read().splitlines(),pfiles[1].read().splitlines())

            #for k, v in r1.items():
            #    print(k)
            diff = compare_f(r1, r2)
            if len(diff) > 0:
                diff.insert(0, each_name+"-DIFF.txt\n\n")
                print(f'writing diff to file ... {each_name}', end="")
                try:
                    diff_f = open(os.path.join(fpath,"DIFF",each_name+"-DIFF.txt",), 'w')
                    diff_f.writelines("%s\n" % l for l in diff)
                    print(' ... DONE')
                except:
                    print("Can't write file: "+os.path.join(fpath,"DIFF",each_name+"-DIFF.txt"))
                    sys.exit(0)
            else: 
                print(f'NO diff ... {each_name}')
    
    if not os.listdir(dfpath):
        print("DONE")
    else:
        print('DONE at - '+dfpath)
        print('Please see the -DIFF files there\n')



def main():
    # two compare file with the same hostname automatically
    #paths = '..\\temp\\config\\config-check-result\\'
    fpath = os.path.join(".","outputs")
    dfpath = os.path.join(".","outputs", "DIFF")
    hostnames = get_hostname_f(fpath)

    go_compare_f(fpath, dfpath, hostnames)


if __name__ == '__main__':
    main()
