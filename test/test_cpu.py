import pytest
from time import time
from src.cpu_checker import is_cpu_spike, time_out

def test_time_out_with_3_seconds():
    assert(time_out(3) == round(time() + 3))

def test_cpu_spike_with_low_percent():
    assert (is_cpu_spike(3, 10, 20) == False)

def test_cpu_spike_with_high_percent():
    assert (is_cpu_spike(3, 40, 20) == True)