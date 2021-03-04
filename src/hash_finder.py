import requests

def find_hash(hash):
    URL = "https://localmonero.co/blocks/api/get_block_header/" + hash
    page = requests.get(URL)
    return page.ok
