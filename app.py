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


def open_database(database_name):
    conn = sqlite3.connect(database_name)
    cursor = conn.cursor()
    return conn, cursor


# Generate salt
def generate_salt():
    return os.urandom(16)


# HASHING
def hash_data(data):
    ph = PasswordHasher()
    hashed = ph.hash(data)
    return hashlib.sha256(hashed.encode()).hexdigest()


def hash_salted_data(data, in_salt):
    ph = PasswordHasher()
    hashed = ph.hash(data, salt=in_salt)
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
        self.hash = hash_salted_data(data + prev_hash, generate_salt())


# Register user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data['username']
    password = data['password']
    user_data = data['data']

    salt = generate_salt()
    hashed_pass = hash_salted_data(password, salt)
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
    hashed_input = hash_salted_data(password, salt)
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


# SYSTEM FUNCTIONS
@app.route('/create_blockchain', methods=['POST'])
def create_blockchain():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    blockchain_type = data['blockchain_type']
    blockchain_password = data['blockchain_password']

    # Create the database if it doesn't exist
    init_db()

    conn, cursor = open_database('blockchain_database.db')

    try:
        # Insert blockchain metadata into the 'blockchains' table
        cursor.execute('INSERT INTO blockchains (name, type, password) VALUES (?, ?, ?)',
                       (blockchain_name, blockchain_type, blockchain_password))

        # Create a new table for the blockchain to store its blocks
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {blockchain_name}
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
             hash TEXT,
             previous_hash TEXT,
             data TEXT,
             reference TEXT)
        ''')

        conn.commit()

        return jsonify({'message': f'Blockchain "{blockchain_name}" created successfully'}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to create blockchain: {str(e)}'}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
    app.run()
