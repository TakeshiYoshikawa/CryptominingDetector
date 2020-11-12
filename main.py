from src.stratum.stratum import *

def run():
    # filename = sniff(count=1000, filter="tcp")
    # wrpcap("pkt/miner.pcap", filename)
    print(findStratum("pkt/miner.pcap"))

    # send_firewall_alert("8.8.8.8")
    # duration = eval(input("How many seconds:"))
    # cpu_spike(duration)
if __name__ == '__main__':
    run()