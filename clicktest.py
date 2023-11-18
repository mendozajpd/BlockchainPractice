import sqlite3
import hashlib
from flask import Flask, g, request, jsonify
import click

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
    conn, cursor = open_database('blockchain_database.db')

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
    conn, cursor = open_database('blockchain_database.db')
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
    conn, cursor = open_database('blockchain_database.db')
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


# Delete Blockchain
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


# Create Blockchain
@click.command()
@click.argument('blockchain_name')
@click.argument('blockchain_type')
@click.argument('blockchain_password')
def create_blockchain(blockchain_name, blockchain_type, blockchain_password):
    # Create the database if it doesn't exist
    init_db()

    conn, cursor = open_database('blockchain_database.db')

    try:
        # Check if the blockchain name already exists
        cursor.execute('SELECT COUNT(*) FROM blockchains WHERE name = ?', (blockchain_name,))
        if cursor.fetchone()[0] > 0:
            click.echo(f'Blockchain "{blockchain_name}" already exists')
            return

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

        click.echo(f'Blockchain "{blockchain_name}" created successfully')
    except Exception as e:
        click.echo(f'Failed to create blockchain: {str(e)}')
    finally:
        conn.close()


# Delete Blockchain
@click.command()
@click.argument('blockchain_name')
def delete_blockchain_cli(blockchain_name):
    result = delete_blockchain(blockchain_name)
    click.echo(result)


# Store Hashed Data in Blockchain
@click.command()
@click.argument('blockchain_name')
@click.argument('data')
@click.argument('reference')
def store_in_blockchain_hashed(blockchain_name, data, reference):
    # Get the latest hash from the blockchain
    latest_hash = get_latest_hash_by_max_id(blockchain_name)

    # Hash the data
    hashed_data = hash_data(data + latest_hash)
    hashed = hash_data(hashed_data + latest_hash)

    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            INSERT INTO {blockchain_name} (hash, previous_hash, data, reference)
            VALUES (?, ?, ?, ?)
        ''', (hashed, latest_hash, hashed_data, reference))

        conn.commit()
        click.echo(f'Data stored in "{blockchain_name}" with hash: {hashed_data}')
    except Exception as e:
        click.echo(f'Failed to store data: {str(e)}')
    finally:
        conn.close()


# Store Data in Blockchain
@click.command()
@click.argument('blockchain_name')
@click.argument('data')
@click.argument('reference')
def store_in_blockchain(blockchain_name, data, reference):
    # Get the latest hash from the blockchain
    latest_hash = get_latest_hash_by_max_id(blockchain_name)
    block_hash = hash_data(data + latest_hash)

    conn, cursor = open_database('blockchain_database.db')

    try:
        cursor.execute(f'''
            INSERT INTO {blockchain_name} (hash, previous_hash, data, reference)
            VALUES (?, ?, ?, ?)
        ''', (block_hash, latest_hash, data, reference))

        conn.commit()
        click.echo(f'Data stored in "{blockchain_name}"')
    except Exception as e:
        click.echo(f'Failed to store data: {str(e)}')
    finally:
        conn.close()


# Delete Reference by ID
@click.command()
@click.argument('blockchain_name')
@click.argument('block_id')
def delete_reference_by_id(blockchain_name, block_id):
    conn, cursor = open_database('blockchain_database.db')

    try:
        # Check if the block with the specified ID exists and has a non-null reference
        cursor.execute(f'''
            SELECT id
            FROM {blockchain_name}
            WHERE id = ? AND reference IS NOT NULL
        ''', (block_id,))
        block = cursor.fetchone()

        if not block:
            click.echo(f'Block with ID {block_id} not found or has a null reference')
            return

        # Delete the reference
        cursor.execute(f'''
            UPDATE {blockchain_name}
            SET reference = NULL
            WHERE id = ?
        ''', (block_id,))
        conn.commit()

        click.echo(f'Reference deleted for block ID {block_id}')
    except Exception as e:
        click.echo(f'Failed to delete reference: {str(e)}')
    finally:
        conn.close()


# Update Block by ID
@click.command()
@click.argument('blockchain_name')
@click.argument('block_id')
@click.argument('new_data')
def update_block_by_id(blockchain_name, block_id, new_data):
    conn, cursor = open_database('blockchain_database.db')

    try:
        # Check if the block with the specified ID exists and has a non-null reference
        cursor.execute(f'''
            SELECT id, hash, previous_hash, data, reference
            FROM {blockchain_name}
            WHERE id = ? AND reference IS NOT NULL
        ''', (block_id,))
        block = cursor.fetchone()

        if not block:
            click.echo(f'Block with ID {block_id} not found or has a null reference')
            return

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
            click.echo(f'Block ID {block_id} updated successfully')
        else:
            click.echo('Failed to update block')
    except Exception as e:
        click.echo(f'Failed to update block: {str(e)}')
    finally:
        conn.close()

# Update Block by Criteria
@click.command()
@click.argument('blockchain_name')
@click.argument('criteria')
@click.argument('value')
@click.argument('new_data')
def update_block_by_criteria(blockchain_name, criteria, value, new_data):
    conn, cursor = open_database('blockchain_database.db')

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
            click.echo(f'No blocks found with {criteria} equal to {value}')
            return

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
            click.echo(f'Block with {criteria}={value} updated successfully. Updated block ID: {block_id}')
        else:
            click.echo('Failed to update block')
    except Exception as e:
        click.echo(f'Failed to update block: {str(e)}')
    finally:
        conn.close()

        # Search in Blockchain

    @click.command()
    @click.argument('blockchain_name')
    @click.argument('criteria')
    @click.argument('value')
    def search_blockchain_cli(blockchain_name, criteria, value):
        result = search_blockchain(blockchain_name, criteria, value)
        if result is not None:
            click.echo(f'Result: {result}')
        else:
            click.echo('No matching data found in the blockchain')

    # Verify Blockchain Integrity
    @click.command()
    @click.argument('blockchain_name')
    def verify_blockchain_cli(blockchain_name):
        result = verify_blockchain_integrity(blockchain_name)
        click.echo(result)
        print(result)
        input("Press Enter to Continue..")

    # Click group
    @click.group()
    def cli():
        pass

    # Add commands to the group
    cli.add_command(create_blockchain)
    cli.add_command(delete_blockchain_cli)
    cli.add_command(store_in_blockchain_hashed)
    cli.add_command(store_in_blockchain)
    cli.add_command(delete_reference_by_id)
    cli.add_command(update_block_by_id)
    cli.add_command(update_block_by_criteria)
    cli.add_command(search_blockchain_cli)
    cli.add_command(verify_blockchain_cli)

    if __name__ == '__main__':
        cli()

