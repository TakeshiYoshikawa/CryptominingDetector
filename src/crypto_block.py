import re
from scapy.all import *
from collections import *
from subprocess import run

def block():
    detected_ips = []
    
    while(True):
        packet_list = sniff(timeout=1, filter="tcp")
        stratum_tag = ['jsonrpc']
        r = re.compile(r'\bjsonrpc\b | \bjob\b | \bblob\b', flags=re.I | re.X)

        for packet in packet_list:
            if(packet[1].haslayer(Raw)): 
                payload_str = linehexdump(packet.load, onlyasc=1, dump=True) #Convert bytes payload to str
                pattern = all(tags in r.findall(payload_str) for tags in stratum_tag)
                # print(payloadStr)

                if(pattern):
                    if(packet[1].dst not in detected_ips):
                        store_miner_ip(packet[1].dst)
                        detected_ips.append(packet[1].dst)
                        send_alert_to_firewall(packet[1].dst)
            else:
                continue
            
def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def store_miner_ip(_ip):
    file = open("src/blacklisted_ips.txt", "a")
    file.write(str(_ip) + "\n")
    file.close

def start():
    block()