''' Draw histogram of counts vs risk for the ip addresses found
    in log4j hits as reported in Splunk.
    - Use the output of parse_ip_from_payload.py, log4j_hosts.csv
    - See plot_frequency_risky_ips.py
'''

# Import the modules
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.pyplot as plt
import dmv_test.mywhois as mywhois
import ipaddress

def ip_only(hosts):
    ## ip_only(df): Return rows where ip is legitimate
    def is_ip(host):
        ## Test if ip address is proper
        try:
            ip_address = ipaddress.ip_address(host)
        except:
            return False
        return True
    return hosts[hosts["ip"].apply(is_ip)].copy()

def fscore(ip_string):
    ## fscore(ipstring): get internet risk score as integer
    r = whois.find(ip_string)
    return int(r["score"]) if r else -1 

def frisk(ip_string):
    ## frisk(ip_string): get internet risk 
    r = whois.find(ip_string)
    return r["risk"] if r else "Unknown"

def plot1(hosts):
    fig, ax = plt.subplots(figsize=(12,6))
    g = sns.histplot(data=hosts, x="risk", ax=ax)
    plt.semilogy(base=2)
    ticks = 2**np.arange(9)  # How do I get 9?
    plt.yticks(ticks, [ f"{x:.0f}" for x in ticks ])
    plt.title("Semilog plot of Count vs Internet Risk of IP")
    plt.show()

def plot2(hosts):
    fig, ax = plt.subplots(figsize=(12,6))
    g1 = sns.histplot(data=hosts, x="score", ax=ax, bins=10)
    plt.semilogy(base=2)
    ticks = 2**np.arange(9)  # How do I get 9?
    plt.yticks(ticks, [ f"{x:.0f}" for x in ticks ])
    plt.title("Semilog plot of Count vs Internet Score of IP")
    plt.show()


# Read in the data
fn =  "log4j_hosts.csv"

# Read the hosts found in the https jndi events returned by the splunk search
raw_hosts = pd.read_csv(fn)

# load the whois database - readonly
whois = mywhois.Risk("../dmv_test/mywhois", readonly=True)

# Clean list by dropping bad ip addresses (probably host names)
hosts = ip_only(raw_hosts)

# Add internet risk score and risk category
myscore = hosts.loc[:,"ip"].apply(fscore).copy()
myrisk  = hosts.loc[:,"ip"].apply(frisk).copy()

hosts.loc[:,"risk"]  = myrisk
hosts.loc[:,"score"] = myscore

# Make risk into a factor category
# See https://stackoverflow.com/questions/67205522/set-order-on-sns-histplot

hosts.risk = pd.Categorical(hosts.risk, ["Unknown", "low", "medium", "high", "very high"])

# Draw plots
plot1(hosts)

plot2(hosts)

