from Block import Block
from cryptography.fernet import Fernet
from argon2 import PasswordHasher, exceptions
import os
import hashlib


blockchain = []


# ENCRYPT
# SALT  + ENCRYPTED
# ARGON HASH
# HASH-256

input_pass = input("Enter a password: ")
stored_pass = '327f04c6861d3a91a7f9c46fac7c26375bedfdb861dde66cd5ad834002427c9b'
# ENCRYPT
# generate fernet key which would be placed within a private blockchain in a database
# create the instance of the Fernet encryptor with the fernet key as the parameter
# generate an encrypted password using encrypt() and add it into a variable

# fernet_key = Fernet.generate_key()
fernet_key = b'uOv6bFZmI3IrR8r6CB0N3lYK66LVA2Vt66lKsHfjpD8='
cipher = Fernet(fernet_key)
encrypted_password = cipher.encrypt(input_pass.encode())

print(encrypted_password)
print(b'gAAAAABlNRZfI3H-FzWHOp8VhcpzNsTMPlL3QQu9jOH_u3Utn5FFRJvp_3LJlMcP4zYYnpEwLBOWDCGJjYqGyvTdfpbj16ClJw==')

# ADD SALT
# generate a SALT then place it in a private blockchain
# add SALT to the encrypted password

# salt = os.urandom(16)  # Generate a random salt
salt = b'\x85\x8a$\xee\x9a-!M\x84\xfa\x7frc\x99\x82n'
combined_data = encrypted_password + salt


# ARGON HASH
# instantiate PasswordHasher() as ph
# use ph to argon hash the combined salt and encrypted password
# place it inside a variable

ph = PasswordHasher()
argon_hashed_data = ph.hash(combined_data).encode("utf-8")



# HASH 256
# take the argon hash and hash it using SHA 256
# place in string variable to then be sent to a private blockchain

final_hash = hashlib.sha256(argon_hashed_data).hexdigest()
# print(final_hash)

if final_hash == stored_pass:
    print("Passwords match.")
else:
    print("Passwords do not match.")










