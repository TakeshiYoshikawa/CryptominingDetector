import pytest
from src.stratum.stratum import *

def test_pcap_created():
    assert create_pcap("test",10) == "pkt/test"
