import sqlite3
from flask import Flask, g, request, jsonify
import hashlib
import os
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
import base64

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


# HASHING
def hash_data(data):
    ph = PasswordHasher()
    hashed = ph.hash(data)
    return hashlib.sha256(hashed.encode()).hexdigest()


def hash_salted_data(data, in_salt):
    ph = PasswordHasher()
    hashed = ph.hash(data, salt=in_salt)
    return hashlib.sha256(hashed.encode()).hexdigest()


# Generate salt
def generate_salt():
    return os.urandom(16)


def generate_salt_as_string():
    salt = os.urandom(16)
    salt_string = base64.b64encode(salt).decode('utf-8')
    return salt_string


# Encrypt/decrypt data
key = Fernet.generate_key()
f = Fernet(key)


def encrypt(data):
    return f.encrypt(data.encode())


def decrypt(data):
    return f.decrypt(data).decode()


class Block:

    def __init__(self, data, prev_hash):
        self.data = data
        self.prev_hash = prev_hash
        self.hash = hash_salted_data(data + prev_hash, generate_salt())


def verify_blockchain_integrity(blockchain_name):
    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data
            FROM {blockchain_name}
            WHERE id != 1
            ORDER BY id
        ''')
        blocks = cursor.fetchall()

        # previous_hash =

        for block in blocks:
            block_id, hash, prev_hash, data = block
            if hash != hash_data(data+previous_hash):
                return jsonify({'error': f'Blockchain tampering detected at block ID {block_id}'})
            previous_hash = hash

        return jsonify({'message': 'Blockchain integrity verified'})
    except Exception as e:
        return jsonify({'error': f'Failed to verify blockchain integrity: {str(e)}'}), 500
    finally:
        conn.close()


def create_genesis_block(blockchain_name):
    conn, cursor = open_database('blockchain_database.db')
    genesis_hash = hash_data("Genesis Block" + generate_salt_as_string())

    try:
        cursor.execute(f'''
            INSERT INTO {blockchain_name} (hash, previous_hash, data, reference)
            VALUES (?, ?, ?, ?)
        ''', (genesis_hash, "0", "The Heavens and the Earth.", "Genesis"))

        conn.commit()
        return jsonify({'message': f'Genesis block created for "{blockchain_name}"'}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to create genesis block: {str(e)}'}), 500
    finally:
        conn.close()


def get_latest_hash_by_max_id(blockchain_name):
    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            SELECT hash
            FROM {blockchain_name}
            WHERE id = (SELECT MAX(id) FROM {blockchain_name})
        ''')
        latest_block = cursor.fetchone()

        if latest_block:
            latest_hash = latest_block[0]
            return latest_hash
        else:
            return "Genesis Block"
    except Exception as e:
        return f'Error: {str(e)}'
    finally:
        conn.close()


# SEARCH THE BLOCKCHAIN
def search_blockchain(blockchain_name, criteria, value):
    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            SELECT data
            FROM {blockchain_name}
            WHERE {criteria} = ?
        ''', (value,))
        result = cursor.fetchall()

        if result:
            return [data[0] for data in result]
        else:
            return None
    except Exception as e:
        return f'Error: {str(e)}'
    finally:
        conn.close()


# IF DATA EXISTS IN BLOCKCHAIN
def is_data_equal_in_blockchain(blockchain_name, criteria, value):
    conn, cursor = open_database('blockchain_database.db')

    try:
        query = f'''
            SELECT COUNT(*)
            FROM {blockchain_name}
            WHERE {criteria} = ?
        '''
        cursor.execute(query, (value,))
        count = cursor.fetchone()[0]

        return count > 0
    except Exception as e:
        return False
    finally:
        conn.close()


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

        create_genesis_block(blockchain_name)

        return jsonify({'message': f'Blockchain "{blockchain_name}" created successfully'}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to create blockchain: {str(e)}'}), 500
    finally:
        conn.close()


# Function to store hashed data in the blockchain
@app.route('/store_in_blockchain_hashed', methods=['POST'])
def store_in_blockchain_hashed():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    data_to_store = data['data']
    reference = data['reference']

    # Get the latest hash from the blockchain
    latest_hash = get_latest_hash_by_max_id(blockchain_name)

    # Hash the data
    hashed_data = hash_data(data_to_store + latest_hash)

    hashed = hash_data(data_to_store + latest_hash)

    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            INSERT INTO {blockchain_name} (hash, previous_hash, data, reference)
            VALUES (?, ?, ?, ?)
        ''', (hashed, latest_hash, hashed_data, reference))

        conn.commit()
        return jsonify({'message': f'Data stored in "{blockchain_name}" with hash: {hashed_data}'}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500
    finally:
        conn.close()


# Function to store data in the blockchain without hashing
@app.route('/store_in_blockchain', methods=['POST'])
def store_in_blockchain():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    data_to_store = data['data']
    reference = data['reference']

    # Get the latest hash from the blockchain
    latest_hash = get_latest_hash_by_max_id(blockchain_name)
    block_hash = hash_data(data_to_store + latest_hash)

    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            INSERT INTO {blockchain_name} (hash, previous_hash, data, reference)
            VALUES (?, ?, ?, ?)
        ''', (block_hash, latest_hash, data_to_store, reference))

        conn.commit()
        return jsonify({'message': f'Data stored in "{blockchain_name}"'}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500
    finally:
        conn.close()


@app.route('/verify_blockchain', methods=['GET'])
def verify_blockchain():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    return verify_blockchain_integrity(blockchain_name)


# TESTING PURPOSES
@app.route('/modify_block_data', methods=['POST'])
def modify_block_data():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    block_id = data['block_id']
    new_data = data['new_data']

    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            UPDATE {blockchain_name}
            SET data = ?
            WHERE id = ?
        ''', (new_data, block_id))
        conn.commit()

        return jsonify({'message': f'Data in block ID {block_id} modified successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to modify block data: {str(e)}'}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
    app.run()
