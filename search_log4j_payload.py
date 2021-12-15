import base64
import csv
import pandas as pd
import numpy as np
import pprint
import urllib.request, urllib.parse, urllib.error
import httplib2
from xml.dom import minidom
import getpass

pp = pprint.PrettyPrinter()

fn = "log64_attempts.12-13-2012.csv"

indexes = " OR ".join(["index="+x for x in """directory_services_nonprod
dmv_google_cloud
doh_google_cloud
dol_google_cloud
dtf_http
estreamer
fireeye
hcr_google_cloud
health_datapower
health_network
its_google_cloud
its_okta_nonprod
main
miauditlogs
os
otda_google_cloud
vmware
webny
webny_nonprod
wineventlog""".split("\n")])


def d64(x):
    # d(b64) decodes base64 byte string. =Nan if there's an error
    try:
        r = base64.b64decode(x, altchars="-_").decode()
    except:
        r = np.nan
    return r

def make_list(events):
    # 
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
    num_column = len(columns)
    len_list   = len(lst)
    len_column = len_list//num_column
    
    df = None
    # Make sure t
    if len_list % len_column != 0:
        print(f"length of lst ({len_list}) must be even multiple of # of names ({num_column})")
        return df
    
    # First column
    df = pd.DataFrame(lst[0::num_column], columns=[columns[0]])
    
    # Remaining columns
    for col in range(1, num_column):
        df[columns[col]] = lst[col::num_column]
    
    return df


# This job makes a real search and outputs the result.
# Assume an authenticated session is open.

import sys
from time import sleep
import splunklib.results as results
import splunklib.client as client

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

# Build a query
earliest_time = "12/13/2021:00:00:00"
latest_time ="-1d@d"
detail = '''Base64 Command "${jndi:*}" | rex "\${jndi.*?Base64\/(?<b64>[^}]*?)}.*" 
| mvexpand b64 | stats values(host) as host earliest(_time) as earliest  by b64 |  mvexpand host 
| convert timeformat="%m/%d/%Y %H:%M:%S" ctime(earliest) as earliest 
| sort host +earliest 
| table host earliest b64'''

query = " ".join(["search earliest=", earliest_time, "latest=", latest_time, indexes, detail])

# searchquery_normal = "search index=main | stats values(sourcetype)"
searchquery_normal = query
# pp.pprint(query)

kwargs_normalsearch = {
#     "earliest_time": "12/09/2021:00:00:00",
#     "latest_time": "-1d@d",
    "search_mode": "normal"
    }

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

# Get the results and display them
# for result in results.ResultsReader(job.results()):
#     print(result)

save_results = job.results()

lst = make_list(save_results)
log = list_to_df(lst, columns=["host", "earliest", "base64_payload"])

# Decode the b64 column into new column, payload
log["payload"] = log.loc[:,"base64_payload"].apply(d64)

# Show the result
#pp.pprint(log[["host", "earliest", "payload"]])

log.to_csv("search_log4j.txt")
job.cancel()   
sys.stdout.write('\n')

