''' Read report of web payload's and get list of unique source hosts
    Usage: parse_ip_from_payload <inputfile> 
'''
import re
import pandas as pd
import numpy as np
import sys
import ipaddress

def fetch_ip(str):
    ''' fetch_ip(str)-->list of ip adresses in string '''
    ippat = r"((?:(?:[0-9]{1,3})(?:\.)){3}(?:[0-9]{1,3}))"
    grp = re.findall(ippat, str)  # findall returns empty group
    return grp

def fetch_host(cmd):
    ''' fetch_host(str)-->list of hosts after http[s] in string '''
    httppat = r"https?:\/\/(?:\?*)([^\/:]+)(?:[\:\/])"
    grp = re.findall(httppat, cmd)
    return grp

def main():
    ''' Read report of web payload's and get list of unique source hosts '''

    # read the search results from the file supplied as an program argument

    fn = opt.fn
    log = pd.read_csv(fn)

    # Clean up
    # Drop any rows that contain Nan. e.g. some of the web paylod's 
    # cannot be converted from base64
    log = log.dropna(subset=["payload"]).reset_index(drop=True)

    ## Find the hosts being referenced in the payload's

    hosts = {}

    grp = []
    for rec, cmd in enumerate(log.payload):
        # Run fetch_ip first to get all the ip addresses
        r1 = [f"{x}" for x in fetch_ip(cmd)]
        # Do not aw2chini,d duplicate ip addresses because fetch_ip found them
        r2 = [f"{x}" for x in fetch_host(cmd) if x not in r1]
        
        grp.extend(r1)
        grp.extend(r2)

    # Deduplicate, make into a df, and output as csv
    if opt.dedup:
        print("Deduping ..")
        hosts = set(grp)
    else:
        print("Not deduping ..")
        hosts = grp

    # Store to host in column named ip to match name used by whois
    # whois will not use any that are not valid ip addresses
    dfhosts = pd.DataFrame(hosts,columns=["ip"])
    dfhosts.to_csv("log4j_hosts.csv",index=False)
    return dfhosts
    

import argparse
parser = argparse.ArgumentParser(description="Parse ip and hosts from file")
#parser.add_argument(prog="parse_ip_from_payload")
parser.add_argument("fn", help="Input file containing ip and hosts")
parser.add_argument("--dedup", action="store_true", help="Deduplicate output")
opt = parser.parse_args()

main()
