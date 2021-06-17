import re
from scapy.all import sniff, Raw, linehexdump
from collections import *
from subprocess import run
from src.hash_checker import is_mining_block

def block():    
    while(True):
        packet_list = sniff(timeout=1, filter="tcp")
        hash_search = re.compile(r'\b[A-Fa-f0-9]{64}\b')

        for packet in packet_list:
            if(packet[1].haslayer(Raw)): 
                #Convert bytes payload to str
                payload_str = linehexdump(packet.load, onlyasc=1, dump=True) 
                
                hash = hash_search.findall(payload_str)
                if(is_mining_block(hash) == True):
                    print("New block detected: {}".format(hash))
                    print("Block address: {}".format(packet[1].src))
                    send_alert_to_firewall(packet[1].src)
            else:
                continue
            
def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def start():
    block()