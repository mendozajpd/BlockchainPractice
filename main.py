from Block import Block
from cryptography.fernet import Fernet #encryption
from argon2 import PasswordHasher, exceptions #hashing
import os


blockchain = []


testblock = Block("First hash",['Username: Nico','Password'])
print(testblock.block_hash)


