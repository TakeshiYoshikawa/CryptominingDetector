import re
from time import sleep
from scapy.all import sniff, Raw, linehexdump
from collections import *
from subprocess import run
from src.hash_checker import is_mining_block

def block():    
    while(True):
        sleep(1)
        packet_list = sniff(timeout=1, filter="tcp")

        for packet in packet_list:
            if(packet[1].haslayer(Raw)): 
                #Convert bytes payload to str
                payload_str = linehexdump(packet.load, onlyasc=1, dump=True) 
                
                _hash = hash_search(payload_str)
                if(is_mining_block(_hash) == True):
                    print("Block Header: {}".format(_hash))
                    print("Server address: {}".format(packet[1].src))
                    # send_alert_to_firewall(packet[1].src)
            else:
                continue

def hash_search(payload) -> str:
    hash_search = re.compile(r'\b[A-Fa-f0-9]{64}\b')
    _hash = hash_search.findall(payload)

    # Hash not found
    if(len(_hash) == 0): 
        return ""
    return str(_hash[0])

def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def start():
    block()