import pytest
from src.stratum.stratum import *

def test_pcap_created():
    assert(create_pcap("test.pcap",10) == "pkt/test.pcap")

def test_time_out_with_3_seconds():
    assert(time_out(3) == round(time() + 3))
