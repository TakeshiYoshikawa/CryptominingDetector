import pytest
from src.stratum.stratum import *

def test_pcap_created():
    assert(create_pcap("test.pcap",10) == "pkt/test.pcap")

def test_time_out_with_3_seconds():
    assert(time_out(3) == round(time() + 3))

def test_cpu_spike_with_low_percent():
    assert (isCpuSpike(3, 10, 20) == False)

def test_cpu_spike_with_high_percent():
    assert (isCpuSpike(3, 40, 20) == True)