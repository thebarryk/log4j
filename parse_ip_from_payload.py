''' Read report of web payload's and get list of source hosts
    Usage: parse_ip_from_payload FN [--dedup] [-o OUTPUT]
    --dedup .. include one event per host at the earliest time it occurred
'''
import re
import pandas as pd
import numpy as np
import sys
import ipaddress
from collections import defaultdict
import argparse

class Myopt():
    def __init__(self, args=None):

        self.description = '''Parse ip and hosts from file'''
        self.p = argparse.ArgumentParser(description=self.description)
        add = self.p.add_argument
        add("fn", help="Input file containing ip and hosts")
        add("--dedup", action="store_true", help="Deduplicate output")
        add("-o", "--output", help="Output file for time, host", default="log4j_hosts.csv")
        if args:
            self.opt = self.p.parse_args(args)
        else:
            self.opt = self.p.parse_args()
            
def fetch_ip(str):
    ''' fetch_ip(str)-->list of ip adresses in string '''
    ippat = r"((?:(?:[0-9]{1,3})(?:\.)){3}(?:[0-9]{1,3}))"
    grp = re.findall(ippat, str)  
    # Worst case: findall returns an empty group
    return grp

def fetch_host(cmd):
    ''' fetch_host(str)-->list of hosts after http[s] in string '''
    httppat = r"https?:\/\/(?:\?*)([^\/:]+)(?:[\:\/])"
    grp = re.findall(httppat, cmd)
    return grp

def main():
    ''' Read report of web payload's and get list of unique source hosts '''

    # read the search results from the file supplied as program argument

    fn = myopt.fn
    # log is dict with columns host, time and payload
    log = pd.read_csv(fn)

    # Drop any rows that contain Nan. e.g. some of the web paylod's
    # cannot be converted from base64
    log = log.dropna(subset=["payload"]).reset_index(drop=True)

    ## Find the hosts being referenced in the payload's

    events = defaultdict(list)
    
    for rec, cmd in enumerate(log.payload):
        
        # Run fetch_ip first to get all the ip addresses
        # Keep the repetitions because each represents another hit
        r1 = [f"{x}" for x in fetch_ip(cmd)]
        
        # Do not add any ip addresses which were already found by fetch_ip 
        r2 = [f"{x}" for x in fetch_host(cmd) if x not in r1]
        
        timestamp = log.time[rec]
        for host in r1 + r2:
            events[host].append(timestamp)

    # Deduplicate by storing only one time, the earliest of e make into a df, and output as csv
    if myopt.dedup:
        print("Deduping ..")
        for host in events:
            earliest = min(events[host])
            events[host] = [earliest]
    else:
        print("Not deduping ..")

# Write csv with columns time, ip
# Store the host in column named ip to match name used by whois
# Note: whois will not use any that are not valid ip addresses
    
    with open(myopt.output,"w") as fout:
        fout.write("time,ip\n")
        for host, times in events.items():
            for ztime in times:
                fout.write(f"{ztime},{host}\n")

# Establish options in global object, myoptions, so it can be used anywhere.

# myoptions = Myopt("all_jndi_hits_2021.csv -o all_jndi_hosts_2021.csv".split())
myoptions = Myopt()
myopt = myoptions.opt  # Makes it easy to get an option e.g. myopt.dedup

main()
print("Done!")


