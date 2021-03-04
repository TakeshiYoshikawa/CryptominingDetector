from bs4.element import SoupStrainer
import requests
import re
from bs4 import BeautifulSoup

# def this_hash_exist(hash):
#     URL = "https://localmonero.co/blocks/api/get_block_header/" + hash
#     while(True):
#         page = requests.get(URL)
#         if(page.status_code == 200):
#             soup = BeautifulSoup(page.content, 'html.parser')

#             r = re.compile(r'"hash":"\b[A-Fa-f0-9]{64}\b"') #Regex to find all SHA256 hashes
                
#             return r.findall(str(soup))
#             #print(r.findall(str(soup))) #Find all hashes in requested page
#         continue

def find_hash(hash):
    URL = "https://localmonero.co/blocks/api/get_block_header/" + hash
    page = requests.get(URL)
    return page.ok
