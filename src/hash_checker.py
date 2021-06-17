import requests
import re

def is_mining_block(hash):
    if(hash != []):
        URL = "https://localmonero.co/blocks/api/get_block_header/" + hash
        page = requests.get(URL)
        response = str(page.json())
        print(response)
        search = re.compile(r'OK')
        status_block = search.findall(response)

        return status_block == ['OK']
    else:
        return False