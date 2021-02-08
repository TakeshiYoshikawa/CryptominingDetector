from bs4.element import SoupStrainer
import requests
import re
from bs4 import BeautifulSoup

# URL = 'https://minergate.com/pool-stats/xmr'
# URL = 'https://minergate.com/blockchain/xmr/blocks'
URL = 'https://minergate.com/blockchain/xmr/transpool'

while(True):
    page = requests.get(URL)
    if(page.status_code == 200):
        parser_param = SoupStrainer('script')
        soup = BeautifulSoup(page.content, 'html.parser', parse_only=parser_param)
        # rows = soup.find_all('script') #rows[2] tem o JSON var initialState que possui as hashes.    
        # rows = soup.find("script", text=lambda text: text and "initialState" in text)

        #Regex to find all SHA256 hashes
        r = re.compile(r'\b[A-Fa-f0-9]{64}\b') 
            
        #Find all hashes in requested page
        print(r.findall(str(soup)))
    continue


"""
hashes = open('hash.txt', 'r')
hashes = hashes.readline()

#Regex to find all SHA256 hashes
r = re.compile(r'\b[A-Fa-f0-9]{64}\b') 
print(r.findall(hashes))
"""