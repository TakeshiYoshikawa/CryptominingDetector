import pytest
from src.crypto_block import hash_search

payload = 'jsonrpc":"2.0","result":{"job":{"blob":"0e0eff9cfe830643c627aa0d9f4ec11e32897143549ddb74aaba95c6ab6c9f86c7dac159604d5400000000af20177365fa567d9062ab3bc80125ef01f0547a4db9b88ec05bade0e0ed06511b","target":"37894100","job_id":"3533617654004306159","time_to_live":5,"height":2343871,"algo":"rx/0","seed_hash":"a6514bf641e3ed0717e150a59ff2df8d1de0af80821f05b9c69493ec2ad29afe"},"status":"OK","id":"2249510252665149914"},"id":"1","error":null'
only_blob = '{"job":{"blob":"0e0eff9cfe830643c627aa0d9f4ec11e32897143549ddb74aaba95c6ab6c9f86c7dac159604d5400000000af20177365fa567d9062ab3bc80125ef01f0547a4db9b88ec05bade0e0ed06511b","target":"37894100","job_id":"3533617654004306159","time_to_live":5,"height":2343871,"algo":"rx/0"'
hash_fragment = '0e0eff9cfe830643c627aa0d9f4ec1'

def test_extract_only_hash_256_in_a_packet():
    assert(hash_search(payload) == "a6514bf641e3ed0717e150a59ff2df8d1de0af80821f05b9c69493ec2ad29afe")

def test_extract_with_a_blob():
    assert(hash_search(only_blob) == "")

def test_with_a_incomplete_hash():
    assert(hash_search(hash_fragment) == "")