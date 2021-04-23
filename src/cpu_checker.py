from time import sleep, time
from numpy import mean
from psutil import cpu_percent, virtual_memory

def time_out(seconds):
    return round(time() + seconds)

def is_cpu_spike(duration, cpu_usage, percent_limit):
    limit_time = time_out(duration)
    while(limit_time > time()):
        # cpu_usage = mean(cpu_percent(interval=1, percpu=True))
        if(cpu_usage >= percent_limit): 
            print("CPU spike detected")
            return True

    return False