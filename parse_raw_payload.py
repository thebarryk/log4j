''' Parse base64 payloads of log4j jndi into readable payloads
    Option:
    -i <fn> Use file with columns host, time, payload
            eg. download all_jndi_payloads.csv ed from saved Splunk search
            > Otherwise, then run splunk search
    Output file has columns host, time, payload (readable)
    -o <fn> Use provided name for output
            > Otherwise write to search_log4j.csv
    --defang Defang the payload so the line don't execute
    See parse_raw_payload.py
'''

import base64
import csv
import pandas as pd
import numpy as np
import urllib.request, urllib.parse, urllib.error
import httplib2
import getpass
import sys
from time import sleep
import splunklib.results as results
import splunklib.client as client
import re

def defang_host(str):
    return re.sub(r"(https?:\/\/)([^\/]+)", r"\1?\2", str)

def defang_ip(str):
    return re.sub(r"((?:(?:[0-9]{1,3})(?:\.)?){4})", r"?\1", str)

def defang(str):
    fang = lambda p, s: re.sub(f"{p}", r"?\1", s)
    try:
        if type(str) == str:
            if len(str) == 0:
                return str
        if type(str) == float:
            if np.isnan(str):
                return str
        r = defang_ip( defang_host( fang("(wget|curl|bash|http)", str) ) )       
    except BaseException as err:
        print(f"Unexpected {err=}, {type(err)=}")
        import pdb; pdb.set_trace()
    return r

def quote_words(str):
    '''quote_words("word1 word2") --> "word1",:word2
       Change string of words into string in quoted csv format
    '''
    return ",".join([ f'"{x}"' for x in str.replace("\n","").split()])

def build_query():
    # Build a query
    # Reminder: earliest_time = "12/13/2021:00:00:00"
    # Returns 
    
    earliest_time = "12/09/2021:00:00:00"
    latest_time ="12/31/2021:00:00:00"

    idx = """directory_services_nonprod doh_google_cloud dol_google_cloud dtf_http estreamer
    fireeye hcr_google_cloud health_datapower health_network its_google_cloud its_okta
    nonprod main miauditlogs os otda_google_cloud vmware webny webny_nonprod wineventlog"""

    indexes = f"index IN ({quote_words(idx)})"

    match = '''Base64 Command "${jndi:*}"'''

    rex = '''| rex max_match=5 
    "({jndi.*?Base64\/(?<b64>(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?))"'''

    stats = '''
    | mvexpand b64 | stats values(host) as host earliest(_time) as earliest by b64 |  mvexpand host 
    | convert timeformat="%m/%d/%Y %H:%M:%S" ctime(earliest) as time 
    | rename b64 as payload
    | sort host +time 
    | table host time payload'''

    query = f"""search earliest={earliest_time}
                latest={latest_time} 
                {indexes} {match} {rex} {stats}"""

    return query

def d64(x):
    ''' d(b64)-->decodes base64 byte string. =Nan if there's an error
    '''
    try:
        r = base64.b64decode(x, altchars="-_").decode()
    except:
        r = np.nan
    return r

def make_list(events):
    '''make_list(events)-->list of the splunk events
    ''' 
    lst = []
    for result in results.ResultsReader(events):
        lst.extend(result.values())
    return lst

def list_to_df(lst, columns):
    '''Create a df with n=len(columns) columns from alist
       0th row has items lst[0] lst[1] ... (n-1)th
       lst row has items lst[0+n] lst[1+n] ... lst[(n-1 + n)i
       ... etc
    '''
    num_columns = len(columns)
    len_list    = len(lst)
    
    # Make sure t
    if len_list % num_columns != 0:
        print(f"length of lst ({len_list}) must be even multiple of # of names ({num_columns})")
        return None
    
    # Reshape the list into a list of lists before returning the dataframe
    sublists = [ lst[i:i+num_columns] for i in range(0, len_list, num_columns) ]
    return pd.DataFrame(sublists, columns=columns)

def run_search():
    """ Return df with columns host, time and payload (base64) from splunk search"""
    def results_to_df(splunk_results):
        lst = make_list(save_results)
        log = list_to_df(lst, columns=["host", "time", "payload"])
        return log

    HOST = "cnsesplunkoperations.svc.ny.gov"
    PORT = 8089
    USERNAME = "bdk01"
    PASSWORD = getpass.getpass()
    OWNER = "bdk01"
    APP = "search"

    # Create a Service instance and log in 
    service = client.connect(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        owner=OWNER,
        app=APP)

    kwargs_normalsearch = {
    #     "earliest_time": "12/09/2021:00:00:00",
    #     "latest_time": "-1d@d",
        "search_mode": "normal"
        }
    searchquery_normal = build_query()

    job = service.jobs.create(searchquery_normal, **kwargs_normalsearch)

    # A normal search returns the job's SID right away, so we need to poll for completion
    while True:
        while not job.is_ready():
            pass
        stats = {"isDone": job["isDone"],
                 "doneProgress": float(job["doneProgress"])*100,
                  "scanCount": int(job["scanCount"]),
                  "eventCount": int(job["eventCount"]),
                  "resultCount": int(job["resultCount"])}

        status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
                  "%(eventCount)d matched   %(resultCount)d results") % stats

        print(f"{status=}")
        sys.stdout.flush()
        if stats["isDone"] == "1":
            sys.stdout.write("\n\nDone!\n\n")
            break
        sleep(2)

    # By default only 100 events are returned. Use count=0 to get all of them to sys limit.
    # See: Splunk Answer 308505
    # https://community.splunk.com/t5/Splunk-Search/Custom-Splunk-search-command-only-returns-100-results/m-p/308505

    save_results = job.results(count=0)
    df = results_to_df(save_results)
    job.cancel()   
    return df

def defanger(log, defanging=False):
    log.columns = ["host", "time", "base64_payload"]
    if defanging:
        log["raw_payload"] = log.loc[:,"base64_payload"].apply(d64)
        # Defang the raw_payload column into new column, payload
        log["payload"] = log.loc[:,"raw_payload"].apply(defang)
    else:
        log["payload"] = log.loc[:,"base64_payload"].apply(d64)

def options(finput=None, foutput=None, defanging=False):
    Usage = "parse_raw_payload [-i <finput>] [-o <foutput>] [--defang]"
    defanging = False
    foutput = "search_log4j.csv"
    args = (x for x in sys.argv)
#     args = (x for x in "-i all_jndi_payloads_2021.csv -o all_jndi_hits_2021.csv".split())
    for arg in args:
        if arg=="-i":
            try:
                finput = next(args)
            except:
                sys.exit(f"{Usage=}")
        if arg == "-o":
            try:
                foutput = next(args)
            except:
                sys.exit(f"{Usage=}")
        if arg == "--defang":
            defanging = True
    return finput, foutput, defanging

def main():
    finput, foutput, defanging = options()
    if finput is None:
        log = run_search()
    else:
        log = pd.read_csv(finput)

    defanger(log, defanging=defanging)
    
    log[["host", "time", "payload"]].to_csv(foutput, index=False)

main()
