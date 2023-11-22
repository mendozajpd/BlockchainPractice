import sqlite3
from flask import Flask, g, request, jsonify, session
import hashlib
import secrets
import uuid

app = Flask(__name__)

# Database config
DATABASE = 'BSS.db'
app.secret_key = 'testsecretkey'


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
        cursor = db.cursor()

        # Create Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users
            (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                email TEXT,
                api_key INTEGER,
                is_admin INTEGER,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                FOREIGN KEY (api_key) REFERENCES api_keys(api_key)
            )
        ''')

        # Create Blockchains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchains
            (
                blockchain_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                blockchain_name TEXT,
                is_public INTEGER,
                blockchain_password TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')

        # API KEYS TABLE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys
            (
                api_key TEXT PRIMARY KEY,
                user_id INTEGER,
                api_name TEXT DEFAULT 'Secret Key',
                created_at TIMESTAMP,
                last_used TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')

        # Create Logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs
            (
                log_id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                blockchain_id INTEGER,
                timestamp TIMESTAMP,
                hash TEXT,
                previous_hash TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (blockchain_id) REFERENCES blockchains(blockchain_id)
            )
        ''')

        db.commit()



# Hashing
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Open database connection
def open_database(database_name):
    conn = sqlite3.connect(database_name)
    cursor = conn.cursor()
    return conn, cursor


# Blockchain Integrity Verification
def verify_blockchain_integrity(blockchain_name):
    conn, cursor = open_database(DATABASE)

    try:
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data
            FROM {blockchain_name}
            WHERE id > 1
            ORDER BY id
        ''')
        blocks = cursor.fetchall()

        previous_hash = ""

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


# Create Genesis Block
def create_genesis_block(blockchain_name):
    conn, cursor = open_database(DATABASE)
    genesis_hash = hash_data("Genesis Block")

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


# Add Block to Blockchain
def add_block(blockchain_name, hash_value, data, reference):
    conn, cursor = open_database(DATABASE)
    previous_hash = get_latest_hash_by_max_id(blockchain_name)

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


# Get Latest Hash from Blockchain
def get_latest_hash_by_max_id(blockchain_name):
    conn, cursor = open_database(DATABASE)

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


# Delete Blockchain
def delete_blockchain(blockchain_name):
    conn, cursor = open_database(DATABASE)

    try:
        # Drop the blockchain table
        cursor.execute(f'DROP TABLE IF EXISTS {blockchain_name}')

        # Delete the blockchain entry from the blockchains table
        cursor.execute('DELETE FROM blockchains WHERE blockchain_name = ?', (blockchain_name,))

        conn.commit()
        return jsonify({'message': f'Blockchain "{blockchain_name}" deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete blockchain: {str(e)}'}), 500
    finally:
        conn.close()

# SEARCH THE BLOCKCHAIN
def search_blockchain(blockchain_name, criteria, value):
    conn, cursor = open_database(DATABASE)
    try:
        cursor.execute(f'''
            SELECT data
            FROM {blockchain_name}
            WHERE {criteria} = ? AND reference IS NOT NULL
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
    conn, cursor = open_database(DATABASE)
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

# LOGGING IN
def is_valid_login(username, password):
    # Query your database to check if the provided username and password are valid
    conn, cursor = open_database(DATABASE)
    password = hash_data(password)
    try:
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()

        return user is not None
    finally:
        conn.close()

def get_user_id(username):
    conn, cursor = open_database(DATABASE)

    try:
        cursor.execute('SELECT user_id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user:
            return user[0]
        else:
            return None
    except Exception as e:
        print(f'Failed to get user ID: {str(e)}')
        return None
    finally:
        conn.close()


# Create Blockchain
@app.route('/create_blockchain', methods=['POST'])
def create_blockchain():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    isPublic = data['isPublic']
    blockchain_password = data['blockchain_password']

    # Create the database if it doesn't exist
    init_db()

    conn, cursor = open_database(DATABASE)

    try:
        # Check if the blockchain name already exists
        cursor.execute('SELECT COUNT(*) FROM blockchains WHERE blockchain_name = ?', (blockchain_name,))
        if cursor.fetchone()[0] > 0:
            return jsonify({'error': f'Blockchain "{blockchain_name}" already exists'}), 400

        # Insert blockchain metadata into the 'blockchains' table
        cursor.execute('INSERT INTO blockchains (blockchain_name, isPublic, blockchain_password, CreatedAt, UpdatedAt) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)',
                       (blockchain_name, int(isPublic), blockchain_password))
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


# Delete Blockchain Endpoint
@app.route('/delete_blockchain', methods=['DELETE'])
def delete_blockchain_endpoint():
    data = request.get_json()
    blockchain_name = data['blockchain_name']

    if not blockchain_name:
        return jsonify({'error': 'Blockchain name is required'}), 400

    return delete_blockchain(blockchain_name)


# Store Hashed Data in Blockchain
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

    conn, cursor = open_database(DATABASE)

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


# Store Data in Blockchain
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

    conn, cursor = open_database(DATABASE)

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


# Delete Reference by ID
@app.route('/delete_reference_by_id', methods=['DELETE'])
def delete_reference_by_id():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    block_id = data['block_id']

    if not blockchain_name or not block_id:
        return jsonify({'error': 'Blockchain name and block ID are required'}), 400

    conn, cursor = open_database(DATABASE)

    try:
        # Check if the block with the specified ID exists and has a non-null reference
        cursor.execute(f'''
            SELECT id
            FROM {blockchain_name}
            WHERE id = ? AND reference IS NOT NULL
        ''', (block_id,))
        block = cursor.fetchone()

        if not block:
            return jsonify({'error': f'Block with ID {block_id} not found or has a null reference'}), 404

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


# Update Block by ID
@app.route('/update_block_by_id', methods=['PUT'])
def update_block_by_id():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    block_id = data['block_id']
    new_data = data['new_data']

    if not blockchain_name or not block_id or not new_data:
        return jsonify({'error': 'Blockchain name, block ID, and new data are required'}), 400

    conn, cursor = open_database(DATABASE)

    try:
        # Check if the block with the specified ID exists and has a non-null reference
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data, reference
            FROM {blockchain_name}
            WHERE id = ? AND reference IS NOT NULL
        ''', (block_id,))
        block = cursor.fetchone()

        if not block:
            return jsonify({'error': f'Block with ID {block_id} not found or has a null reference'}), 404

        block_id, hash_value, _, old_data, old_reference = block

        # Get the latest hash from the blockchain
        latest_hash = get_latest_hash_by_max_id(blockchain_name)

        # Delete the old reference
        cursor.execute(f'''
            UPDATE {blockchain_name}
            SET reference = NULL
            WHERE id = ?
        ''', (block_id,))
        conn.commit()

        # Add a new block with the updated data
        new_block_hash = hash_data(new_data + latest_hash)
        if add_block(blockchain_name, new_block_hash, new_data, old_reference):
            return jsonify({'message': f'Block ID {block_id} updated successfully'}), 200
        else:
            return jsonify({'error': 'Failed to update block'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to update block: {str(e)}'}), 500
    finally:
        conn.close()


# Update Block by Criteria
@app.route('/update_block_by_criteria', methods=['PUT'])
def update_block_by_criteria():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    criteria = data['criteria']
    value = data['value']
    new_data = data['new_data']

    if not blockchain_name or not criteria or not value or not new_data:
        return jsonify({'error': 'Blockchain name, criteria, value, and new data are required'}), 400

    conn, cursor = open_database(DATABASE)

    try:
        # Check if there are blocks with the specified criteria
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data, reference
            FROM {blockchain_name}
            WHERE {criteria} = ? AND reference IS NOT NULL
            ORDER BY id DESC
        ''', (value,))
        blocks = cursor.fetchall()

        if not blocks:
            return jsonify({'error': f'No blocks found with {criteria} equal to {value}'}), 404

        # Update the block with the highest ID
        latest_block = blocks[0]
        block_id, hash_value, _, old_data, old_reference = latest_block

        # Get the latest hash from the blockchain
        latest_hash = get_latest_hash_by_max_id(blockchain_name)

        # Delete the old reference
        cursor.execute(f'''
            UPDATE {blockchain_name}
            SET reference = NULL
            WHERE id = ?
        ''', (block_id,))
        conn.commit()

        # Add a new block with the updated data
        new_block_hash = hash_data(new_data + latest_hash)
        if add_block(blockchain_name, new_block_hash, new_data, old_reference):
            return jsonify({
                'message': f'Block with {criteria}={value} updated successfully. Updated block ID: {block_id}'
            }), 200
        else:
            return jsonify({'error': 'Failed to update block'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to update block: {str(e)}'}), 500
    finally:
        conn.close()


# Search in Blockchain
@app.route('/search_in_blockchain', methods=['GET'])
def search_blockchain_endpoint():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    criteria = data['criteria']
    value = data['value']

    if not blockchain_name or not criteria or not value:
        return jsonify({'error': 'Blockchain name, criteria, and value are required'}), 400

    result = search_blockchain(blockchain_name, criteria, value)

    if result is not None:
        return jsonify({'result': result}), 200
    else:
        return jsonify({'message': 'No matching data found in the blockchain'}), 404

# List Blockchains
@app.route('/list_blockchains', methods=['GET'])
def list_blockchains():
    conn, cursor = open_database(DATABASE)
    try:
        cursor.execute('SELECT blockchain_name FROM blockchains')
        blockchains = [row[0] for row in cursor.fetchall()]
        return jsonify({'blockchains': blockchains}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch blockchains: {str(e)}'}), 500
    finally:
        conn.close()

# List References in Blockchain
@app.route('/list_references', methods=['GET'])
def list_references():
    data = request.get_json()
    blockchain_name = data['blockchain_name']

    if not blockchain_name:
        return jsonify({'error': 'Blockchain name is required'}), 400

    conn, cursor = open_database(DATABASE)

    try:
        cursor.execute(f'''
            SELECT reference
            FROM {blockchain_name}
            WHERE reference IS NOT NULL
        ''')
        references = [row[0] for row in cursor.fetchall()]

        if references:
            return jsonify({'references': references}), 200
        else:
            return jsonify({'message': f'No references found for {blockchain_name}'}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to list references: {str(e)}'}), 500
    finally:
        conn.close()


# Verify Blockchain Integrity Endpoint
@app.route('/verify_blockchain', methods=['GET'])
def verify_blockchain():
    data = request.get_json()
    blockchain_name = data['blockchain_name']
    return verify_blockchain_integrity(blockchain_name)


# User Creation
@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']
    is_admin = data.get('is_admin', False)  # Default to False if not provided

    # Check if the username already exists
    if is_data_equal_in_blockchain('Users', 'Username', username):
        return jsonify({'error': f'Username "{username}" already exists'}), 400

    # Hash the password before storing it in the database
    hashed_password = hash_data(password)

    conn, cursor = open_database(DATABASE)

    try:
        # Insert user data into the 'Users' table
        cursor.execute('''
            INSERT INTO Users (Username, Password, Email, isAdmin, CreatedAt, UpdatedAt)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (username, hashed_password, email, int(is_admin)))

        conn.commit()

        return jsonify({'message': f'User "{username}" created successfully'}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to create user: {str(e)}'}), 500
    finally:
        conn.close()

# Register User
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if the username is already taken
    if is_username_taken(username):
        return jsonify({'error': 'Username is already taken'}), 400

    # Hash the password before storing it
    hashed_password = hash_data(password)

    conn, cursor = open_database(DATABASE)

    try:
        # Insert the new user into the 'users' table
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()

        return jsonify({'message': f'User "{username}" registered successfully'}), 201

    except Exception as e:
        return jsonify({'error': f'Failed to register user: {str(e)}'}), 500

    finally:
        conn.close()


# LOGGING IN
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the username and password are valid (you should replace this with your authentication logic)
    if is_valid_login(username, password):
        # Check if the user is already logged in
        if session.get('logged_in'):
            return jsonify({'error': 'User is already logged in'}), 400

        # Set the user as logged in using Flask session
        session['logged_in'] = True
        session['username'] = username

        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    # Check if the user is logged in before attempting to logout
    if session.get('logged_in'):
        # Clear the session
        session.clear()
        return jsonify({'message': 'Logout successful'}), 200
    else:
        return jsonify({'error': 'Not logged in'}), 401



# API
@app.route('/generate_api_key', methods=['POST'])
def generate_api_key():
    # Check if the user is logged in
    if not g.logged_in or not session.get('username'):
        return jsonify({'error': 'Unauthorized'}), 401

    # Generate a random API key (UUID)
    api_key = str(uuid.uuid4())

    # Get the user ID based on the logged-in username
    username = session.get('username')
    user_id = get_user_id(username)

    if user_id is None:
        return jsonify({'error': 'User not found'}), 404

    # Get the API name from the request or use the default
    api_name = request.get_json().get('api_name', 'Secret Key')

    # Add the API key to the APIKeys table
    conn, cursor = open_database(DATABASE)

    try:
        print(f'api_key: {api_key}, user_id: {user_id}, api_name: {api_name}')

        cursor.execute('''
            INSERT INTO api_keys (api_key, user_id, api_name, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (api_key, user_id, api_name))

        conn.commit()

        return jsonify({'api_key': api_key, 'api_name': api_name}), 201
    except Exception as e:
        print(f'Error: {str(e)}')
        return jsonify({'error': f'Failed to generate API key: {str(e)}'}), 500
    finally:
        conn.close()




# Should include more
dummy_api_keys = ["doesntmatter"]



@app.before_request
def before_request():
    api_key = request.headers.get('apikey')
    if not api_key or api_key not in dummy_api_keys:
        return jsonify({'error': 'Unauthorized'}), 401

    # Check if the user is logged in
    g.logged_in = session.get('logged_in', False)

if __name__ == '__main__':
    init_db()
    app.run()