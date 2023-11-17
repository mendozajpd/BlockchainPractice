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
    return hashlib.sha256(data.encode()).hexdigest()


def hash_salted_data(data, in_salt):
    ph = PasswordHasher()
    hashed = ph.hash(data, salt=in_salt)
    return hashlib.sha256(hashed.encode()).hexdigest()


def get_block_hash_by_id(conn, cursor, blockchain_name, block_id):
    try:
        cursor.execute(f'''
            SELECT hash
            FROM {blockchain_name}
            WHERE id = ?
        ''', (block_id,))
        result = cursor.fetchone()

        if result:
            block_hash = result[0]
            return block_hash
        else:
            return jsonify({'error': f'Block with ID {block_id} not found'}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to get block hash: {str(e)}'}), 500


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


import sqlite3
import hashlib

def open_database(database_name):
    conn = sqlite3.connect(database_name)
    cursor = conn.cursor()
    return conn, cursor

def hash_data(data):
    # You can use your hash function here, I'll use a simple hashlib example
    return hashlib.sha256(data.encode()).hexdigest()


def verify_blockchain_integrity(blockchain_name):
    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data
            FROM {blockchain_name}
            WHERE id > 1
            ORDER BY id
        ''')
        blocks = cursor.fetchall()

        previous_hash = ""  # Initialize with an empty string

        for block in blocks:
            block_id, hash, prev_hash, data = block
            calculated_hash = hash_data(data + prev_hash)
            if hash != calculated_hash:
                return {'error': f'Blockchain tampering detected at block ID {block_id}'}

        return {'message': 'Blockchain integrity verified'}
    except Exception as e:
        return {'error': f'Failed to verify blockchain integrity: {str(e)}'}
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


# Helper function to add a block
def add_block(blockchain_name, hash_value, previous_hash, data, reference):
    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            INSERT INTO {blockchain_name} (hash, previous_hash, data, reference)
            VALUES (?, ?, ?, ?)
        ''', (hash_value, previous_hash, data, reference))

        conn.commit()
        return True
    except Exception as e:
        print(f'Failed to add block: {str(e)}')
        return False
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


# DELETE THE BLOCKCHAIN
def delete_blockchain(blockchain_name):
    conn, cursor = open_database('blockchain_database.db')

    try:
        # Drop the blockchain table
        cursor.execute(f'DROP TABLE IF EXISTS {blockchain_name}')

        # Delete the blockchain entry from the blockchains table
        cursor.execute('DELETE FROM blockchains WHERE name = ?', (blockchain_name,))

        conn.commit()
        return jsonify({'message': f'Blockchain "{blockchain_name}" deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete blockchain: {str(e)}'}), 500
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


# Delete a blockchain endpoint
@app.route('/delete_blockchain', methods=['DELETE'])
def delete_blockchain_endpoint():
    data = request.get_json()
    blockchain_name = data['blockchain_name']

    if not blockchain_name:
        return jsonify({'error': 'Blockchain name is required'}), 400

    return delete_blockchain(blockchain_name)


# Function to store hashed data in the blockchain
@app.route('/store_in_blockchain_hashed', methods=['POST'])
def store_in_blockchain_hashed():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    data_to_store = data['data']
    reference = data['reference']

    if not reference:
        return jsonify({'error': 'Reference field is required'}), 400

    # Get the latest hash from the blockchain
    latest_hash = get_latest_hash_by_max_id(blockchain_name)

    # Hash the data
    hashed_data = hash_data(data_to_store + latest_hash)

    hashed = hash_data(hashed_data + latest_hash)

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

    if not reference:
        return jsonify({'error': 'Reference field is required'}), 400

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


# Function to delete a reference by ID
@app.route('/delete_reference_by_id', methods=['DELETE'])
def delete_reference_by_id():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    block_id = data['block_id']

    if not blockchain_name or not block_id:
        return jsonify({'error': 'Blockchain name and block ID are required'}), 400

    conn, cursor = open_database('blockchain_database.db')

    try:
        # Check if the block with the specified ID exists
        cursor.execute(f'''
            SELECT id
            FROM {blockchain_name}
            WHERE id = ?
        ''', (block_id,))
        block = cursor.fetchone()

        if not block:
            return jsonify({'error': f'Block with ID {block_id} not found'}), 404

        # Delete the reference
        cursor.execute(f'''
            UPDATE {blockchain_name}
            SET reference = NULL
            WHERE id = ?
        ''', (block_id,))
        conn.commit()

        return jsonify({'message': f'Reference deleted for block ID {block_id}'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete reference: {str(e)}'}), 500
    finally:
        conn.close()


# Function to update a block by ID
@app.route('/update_block_by_id', methods=['PUT'])
def update_block_by_id():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    block_id = data['block_id']
    new_data = data['new_data']

    if not blockchain_name or not block_id or not new_data:
        return jsonify({'error': 'Blockchain name, block ID, and new data are required'}), 400

    conn, cursor = open_database('blockchain_database.db')

    try:
        # Check if the block with the specified ID exists
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data, reference
            FROM {blockchain_name}
            WHERE id = ?
        ''', (block_id,))
        block = cursor.fetchone()

        if not block:
            return jsonify({'error': f'Block with ID {block_id} not found'}), 404

        block_id, hash_value, previous_hash, old_data, old_reference = block

        # Delete the old reference
        cursor.execute(f'''
            UPDATE {blockchain_name}
            SET reference = NULL
            WHERE id = ?
        ''', (block_id,))
        conn.commit()

        # Add a new block with the updated data
        new_block_hash = hash_data(new_data + previous_hash)
        if add_block(blockchain_name, new_block_hash, hash_value, new_data, old_reference):
            return jsonify({'message': f'Block ID {block_id} updated successfully'}), 200
        else:
            return jsonify({'error': 'Failed to update block'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to update block: {str(e)}'}), 500
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
