import hashlib

class Block:
    def __init__(self, previous_hash, data):
        self.data = data
        self.previous_hash = previous_hash

        string_to_hash = "".join(data) + previous_hash
        self.block_hash = hashlib.sha256(string_to_hash.encode()).hexdigest()


