''' Read report of web payload's and get list of unique source hosts '''
import re
import pandas as pd
import numpy as np
import sys

def fetch_ip(str):
    ''' fetch_ip(str)-->list of ip adresses in string
    '''
#     ippat = r"((?:[0-9]{1,3})\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})\.(?:[0-9]{1,3}))"
    ippat = r"((?:(?:[0-9]{1,3})(?:\.)){3}(?:[0-9]{1,3}))"
    grp = re.findall(ippat, str)
    grp = [] if not grp else grp
    return grp

def fetch_host(cmd):
    httppat = r"https?:\/\/(?:\?*)([^\/:]+)(?:[\:\/])"
    grp = re.findall(httppat, cmd)
    r = [] if not grp else grp
    return r

def main():
    ''' Read report of web payload's and get list of unique source hosts '''

    # read the search results from the file supplied as an program argument
    fn = sys.argv[1]
    log = pd.read_csv(fn)

    # Clean up
    # Drop any rows that contain Nan. e.g. some of the web paylod's 
    # cannot be converted from base64
    log = log.dropna(subset=["payload"]).reset_index(drop=True)

    ## Find the hosts being referenced in the payload's

    hosts = {}

    grp = []
    for rec, cmd in enumerate(log.payload):
        r1 = [f"{x}" for x in fetch_ip(cmd)]
        r2 = [f"{x}" for x in fetch_host(cmd)]
        
        grp.extend(r1)
        grp.extend(r2)

    # Deduplicate, make into a df, and output as csv
    hosts = set(grp)

    # Store to host in column named ip to match name used by whois
    # whois will not use any that are not valid ip addresses
    dfhosts = pd.DataFrame(hosts,columns=["ip"])
    dfhosts.to_csv("log4j_hosts.csv",index=False)
    return dfhosts
    
main()
