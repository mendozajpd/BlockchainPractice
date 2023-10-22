from Block import Block
from cryptography.fernet import Fernet #encryption
from argon2 import PasswordHasher, exceptions #hashing
import os


blockchain = []

# Generate a Fernet key (encryption key)
#fernet_key = Fernet.generate_key()
fernet_key = b'uOv6bFZmI3IrR8r6CB0N3lYK66LVA2Vt66lKsHfjpD8='
#salt = os.urandom(16)  # Generate a random salt
salt = b'\x85\x8a$\xee\x9a-!M\x84\xfa\x7frc\x99\x82n'

# Create an Argon2 password hasher
ph = PasswordHasher()

# Store this securely in your database
stored_hashed_password = '$argon2id$v=19$m=65536,t=3,p=4$0mVnvqgGd04KjB7FLzqttg$wD5h2I5rVFHiW6jHL4c7/+KO25M0Zm7pXw6EKsLOTiY'

# User input password
user_input_password = input("Please input password: ")

# Encrypt the password using Fernet
cipher = Fernet(fernet_key)
encrypted_password = cipher.encrypt(user_input_password.encode())

# Combine the salt and the password
combined_data = salt + encrypted_password

# Hash the combined data using Argon2
hashed_combined_data = ph.hash(combined_data).encode("utf-8")

print(fernet_key)
print("Stored pass: " + stored_hashed_password)
# print("Final hash: " + hashed_combined_data)

# Check if the input password matches the stored password
try:
    # Retrieve the salt and stored hashed password from your database
    # In this example, we're using the salt and stored_hashed_password generated earlier

    # Combine the salt and the input password
    # combined_data = salt + cipher.encrypt(user_input_password.encode())

    # Verify the combined data against the stored hashed password
    ph.verify(hashed_combined_data, hashed_combined_data)
    print("Password is correct.")
except exceptions.VerifyMismatchError:
    print("Password is incorrect. Old Password is now Overwritten with new")




# encrypt
# combine salt then hash
# verify
