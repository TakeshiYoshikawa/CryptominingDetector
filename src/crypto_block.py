import re
from scapy.all import sniff, Raw, linehexdump
from collections import *
from subprocess import run
from src.hash_checker import is_mining_block


def block():
    detected_ips = []
    
    while(True):
        packet_list = sniff(timeout=1, filter="tcp")
        stratum_headers = ['jsonrpc']
        
        search = re.compile(r'jsonrpc | job | blob', flags=re.I | re.X)
        hash_search = re.compile(r'\b[A-Fa-f0-9]{64}\b')

        for packet in packet_list:
            if(packet[1].haslayer(Raw)): 
                payload_str = linehexdump(packet.load, onlyasc=1, dump=True) #Convert bytes payload to str
                pattern = all(tags in search.findall(payload_str) for tags in stratum_headers) #Checks if all keywords have been encountered
                
                hash = hash_search.findall(payload_str)
                #print(search.findall(payload_str))
                if(is_mining_block(hash) == True):
                    #print("New block detected: {}".format(hash))
                    #print("Block address: {}".format(packet[1].src))
                    send_alert_to_firewall(packet[1].src)
                
                '''
                if(pattern):
                    if(packet[1].dst not in detected_ips):
                        store_miner_ip(packet[1].dst)
                        detected_ips.append(packet[1].dst)
                        send_alert_to_firewall(packet[1].dst)
                '''
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