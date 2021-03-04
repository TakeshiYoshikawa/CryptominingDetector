import requests
import re

def is_mining_block(hash):
    URL = "https://localmonero.co/blocks/api/get_block_header/" + hash
    page = requests.get(URL)
    response = str(page.json())

    search = re.compile(r'OK')
    status_block = search.findall(response)

    return status_block == ['OK']