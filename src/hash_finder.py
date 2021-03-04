from bs4.element import SoupStrainer
import requests
import re
from bs4 import BeautifulSoup

def find_hash(hash):
    URL = "https://localmonero.co/blocks/api/get_block_header/" + hash
    page = requests.get(URL)
    return page.ok
