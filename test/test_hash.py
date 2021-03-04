import pytest
from src.hash_finder import is_mining_block

def test_transaction_hash():
    assert(is_mining_block("44395a52d6722815be370fd739a743c8f7ec6f6f2fcd93083e220f9d2cf47e91") == False)

def test_with_a_mining_block_hash():
    assert(is_mining_block("1512a9cfba3cca2df4958f70af4dc87a5695a96d8f6683b9715023cce1f6dbee") == True)