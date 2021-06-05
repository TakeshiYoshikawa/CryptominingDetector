import re
from scapy.all import sniff, Raw, linehexdump
from src.hash_checker import is_mining_block
from collections import *
from subprocess import run
from time import sleep

def start():
    block()

def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def is_sending_a_miner_challenge(payload):
    return payload != []

def block():
    detected_ips = []
    
    while(True):
        packet_list = sniff(timeout=1, filter="tcp")        
        client_packet = re.compile(r'"method":"submit"|"result":"[A-Fa-f0-9]{64}"|nonce":"[0-9a-fA-f]{8}"')

        for packet in packet_list:
            if(packet[1].haslayer(Raw)): 
                #Convert bytes payload to string
                payload_str = linehexdump(packet.load, onlyasc=1, dump=True) 
                
                match = is_sending_a_miner_challenge(client_packet.findall(payload_str))
                
                if(match):
                    print("Blocking communication from server (IP:{})".format(packet[1].dst))
                    #send_alert_to_firewall(packet[1].dst)
            sleep(1)