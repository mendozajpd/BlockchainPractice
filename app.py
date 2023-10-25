import sqlite3
from flask import Flask, g, request, jsonify
import hashlib
import os
from cryptography.fernet import Fernet
from argon2 import PasswordHasher

app = Flask(__name__)

# Database config
DATABASE = 'blockchain_database.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# SQLite schema
def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
        CREATE TABLE IF NOT EXISTS blockchains
        (id INTEGER PRIMARY KEY AUTOINCREMENT, 
         name TEXT,
         type TEXT,
         password TEXT)
    ''')
        db.commit()


# Generate salt
def generate_salt():
    return os.urandom(16)


# Hash password
def hash_password(password, in_salt):
    ph = PasswordHasher()
    hashed = ph.hash(password, salt=in_salt)
    return hashlib.sha256(hashed.encode()).hexdigest()


# Encrypt/decrypt data
key = Fernet.generate_key()
f = Fernet(key)


def encrypt(data):
    return f.encrypt(data.encode())


def decrypt(data):
    return f.decrypt(data).decode()


# Blockchain 
blockchain = []


class Block:

    def __init__(self, data, prev_hash):
        self.data = data
        self.prev_hash = prev_hash
        self.hash = hash_password(data + prev_hash, generate_salt())


# Register user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data['username']
    password = data['password']
    user_data = data['data']

    salt = generate_salt()
    hashed_pass = hash_password(password, salt)
    print(hashed_pass)

    encrypted_data = encrypt(user_data)

    db = get_db()
    db.execute('''INSERT INTO users
                 (username, salt, hash, data) 
                 VALUES (?,?,?,?)''',
               (username, salt, hashed_pass, encrypted_data))
    db.commit()

    last_block = blockchain[-1] if blockchain else None
    block = Block(hashed_pass, last_block.hash if last_block else '')
    blockchain.append(block)

    return jsonify({'msg': 'Registered successfully'}), 200


# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Get user from database
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', [username]).fetchone()

    # Unpack user data
    user_id, username, salt, hashed, encrypted_data = user
    # Validate password
    hashed_input = hash_password(password, salt)
    print(hashed_input)
    if hashed_input != hashed:
        return jsonify({'msg': 'Invalid credentials'}), 401

    # Verify blockchain 
    stored_hash = None
    for block in blockchain:
        if block.data == hashed:
            stored_hash = hashed
            break

    if not stored_hash:
        return jsonify({'msg': 'Blockchain verification failed'}), 401

    # Login successful
    return jsonify({'msg': 'Logged in successfully'}), 200


blockchains = []


# CREATE BLOCKCHAIN
@app.route('/create_blockchain', methods=['POST'])
def create_blockchain():
    data = request.get_json()
    blockchain_name = data.get('name')
    blockchain_type = data.get('type')
    blockchain_password = data.get('password')

    # Create the database if it doesn't exist
    init_db()

    conn = sqlite3.connect('blockchain_database.db')
    cursor = conn.cursor()

    # Insert blockchain metadata into the 'blockchains' table
    cursor.execute('INSERT INTO blockchains (name, type, password) VALUES (?, ?, ?)',
                   (blockchain_name, blockchain_type, blockchain_password))

    conn.commit()
    conn.close()

    # Create a new table for the blockchain to store its blocks
    conn = sqlite3.connect('blockchain_database.db')
    cursor = conn.cursor()
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {blockchain_name}
        (id INTEGER PRIMARY KEY AUTOINCREMENT, 
         hash TEXT,
         previous_hash TEXT,
         data TEXT,
         reference TEXT)
    ''')

    conn.commit()
    conn.close()

    return jsonify({'message': f'Blockchain "{blockchain_name}" created successfully'}), 201


if __name__ == '__main__':
    init_db()
    app.run()
