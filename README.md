# CryptominingDetector
 
## Use virtualenv

### Create virtual environment

* ```virtualenv env``` or ```python3 -m venv ./env/```

### Activate virtual environment

* Linux: ```source env/bin/activate```
* Windows: ```/env/Scripts/activate```

## Install requirements in virtualenv

* ```pip install -r requirements.txt```

### When you want to leave virtualenv

* ```deactivate```

## Check firewall table for blocked IPs
* ```iptables -L INPUT -n --line-numbers```

## Run Tests

### Install pytest

* ```sudo apt install python3-pytest ```

### Execute tests

* ```pytest-3 test/```