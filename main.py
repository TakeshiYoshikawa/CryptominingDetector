import re
import scapy.all as sc
from collections import *


def send_firewall_alert():
    pass

def is_stratum_protocol(filename):
    with open(filename) as f:
        data = f.read().splitlines()

    stratum_input = ['login', 'agent']
    stratum_output = ['job_id', 'blob', 'target', 'result']
    r = re.compile(r'\blogin\b | \bagent\b | \bjob_id\b | \bblob\b | \btarget\b | \bresult\b', flags=re.I | re.X)
    stratum_flags = []
    
    for count, line in enumerate(data, 1):
        result = all(tags in r.findall(line) for tags in stratum_input)
        result2 = all(tags in r.findall(line) for tags in stratum_output)

        if(result):
            # print("Stratum input detected on line", count)
            stratum_flags.append(True)
        elif(result2):
            # print("Stratum output detected on line", count) 
            stratum_flags.append(True)
        elif(stratum_flags[0] and stratum_flags[1]):
            return True

    return False

if __name__ == '__main__':
    print(is_stratum_protocol('transactions.txt'))