import requests
import re

def is_mining_block(hash):
    if(hash != []):
        URL = "https://localmonero.co/blocks/api/get_block_header/" + hash[0]
        page = requests.get(URL)
        response = str(page.json())

        search = re.compile(r'OK')
        status_block = search.findall(response)

        return status_block == ['OK']
    else:
        return False