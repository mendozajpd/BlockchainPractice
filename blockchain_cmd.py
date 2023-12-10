import argparse
import cmd2
import requests
from cmd2 import Cmd2ArgumentParser
import json
import argcomplete
from flask import request


def return_message(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('message', '')
    return response_txt

def return_result(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('result', '')
    return response_txt

def return_results(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('results', '')
    return response_txt

def return_error(errormsg):
    try:
        json_response = json.loads(errormsg)
        response_txt = json_response.get('error', '')
    except json.JSONDecodeError:
        # Handle the case when the response is not in JSON format
        response_txt = errormsg

    return response_txt

def return_blockchains(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('blockchains', '')
    return response_txt

def return_users(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('users', '')
    return response_txt

def return_selected(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('selected_blockchain', '')
    return response_txt

def return_username(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('username', '')
    return response_txt

def return_usertype(msg):
    json_response = json.loads(msg)
    response_txt = json_response.get('is_admin','')
    return response_txt

class BlockchainCmd(cmd2.Cmd):

    def __init__(self, api_key):
        super().__init__()
        self.api_address = ""
        self.api_key = api_key
        self.server_url = 'http://127.0.0.1:5000'
        self.session_cookie = ""
        self.set_window_title("Blockchain Security System CLI")
        self.username = ""  # Set username dynamically
        self.user_type = ""
        self.selected_blockchain = ""  # Set selected blockchain dynamically
        self.prompt = f"BSS:{self.user_type}:{self.username}:{self.selected_blockchain}>"
        # add keyname

    def update_prompt(self):
        self.prompt = f"BSS:{self.user_type}:{self.username}:{self.selected_blockchain}>"

    # Select blockchain
    select_parser = Cmd2ArgumentParser()
    select_parser.add_argument('-bn', '--blockchain_name')

    # Deselect blockchain
    deselect_parser = Cmd2ArgumentParser()

    # Create blockchain
    create_parser = Cmd2ArgumentParser()
    create_parser.add_argument('-bn', '--blockchain_name')
    create_parser.add_argument('-pub', '--is_public', choices=['1','0'])
    create_parser.add_argument('-pass', '--blockchain_password')

    # Delete blockchain
    delete_parser = Cmd2ArgumentParser()
    delete_parser.add_argument('-bn', '--blockchain_name')

    # Verify blockchain
    verify_parser = Cmd2ArgumentParser()
    verify_parser.add_argument('-bn', '--blockchain_name')

    # Store
    store_parser = Cmd2ArgumentParser()
    store_parser.add_argument('-bn', '--blockchain_name')
    store_parser.add_argument('-d', '--data')
    store_parser.add_argument('-r', '--reference')

    # Store HASHED
    store_hashed_parser = Cmd2ArgumentParser()
    store_hashed_parser.add_argument('-bn', '--blockchain_name')
    store_hashed_parser.add_argument('-d', '--data')
    store_hashed_parser.add_argument('-r', '--reference')

    # Search
    search_parser = Cmd2ArgumentParser()
    search_parser.add_argument('-bn', '--blockchain_name')
    search_parser.add_argument('-c', '--criteria')
    search_parser.add_argument('-v', '--value')

    # Display Search
    display_search_results_parser = Cmd2ArgumentParser()

    # Get Search Index
    get_search_index_parser = Cmd2ArgumentParser()
    get_search_index_parser.add_argument('-i','--index')

    # Update
    update_parser = Cmd2ArgumentParser()
    update_parser.add_argument('-bn', '--blockchain_name')
    update_parser.add_argument('-c', '--criteria')
    update_parser.add_argument('-v', '--value')
    update_parser.add_argument('-n', '--new_data')

    # Update Block by ID
    update_block_by_id_parser = Cmd2ArgumentParser()
    update_block_by_id_parser.add_argument('-bn', '--blockchain_name')
    update_block_by_id_parser.add_argument('-id', '--block_id')
    update_block_by_id_parser.add_argument('-n', '--new_data')

    # Delete
    delete_reference_parser = Cmd2ArgumentParser()
    delete_reference_parser.add_argument('-bn', '--blockchain_name')
    delete_reference_parser.add_argument('-id', '--block_id')

    # Delete Reference by Criteria
    delete_reference_by_criteria_parser = Cmd2ArgumentParser()
    delete_reference_by_criteria_parser.add_argument('-bn', '--blockchain_name')
    delete_reference_by_criteria_parser.add_argument('-c', '--criteria')
    delete_reference_by_criteria_parser.add_argument('-v', '--value')

    # Select Blockchain
    select_blockchain_parser =Cmd2ArgumentParser()
    select_blockchain_parser.add_argument('selected_blockchain')

    # List Blockchains
    list_blockchains_parser = Cmd2ArgumentParser()

    # List References
    list_references_parser = Cmd2ArgumentParser()
    list_references_parser.add_argument('-bn', '--blockchain_name')

    # Create User
    create_user_parser = Cmd2ArgumentParser()
    create_user_parser.add_argument('-u', '--username')
    create_user_parser.add_argument('-p', '--password')
    create_user_parser.add_argument('-a', '--is_admin', choices=['1', '0'])

    # Register
    register_parser = Cmd2ArgumentParser()
    register_parser.add_argument('-u', '--username')
    register_parser.add_argument('-p', '--password')

    # Login
    login_parser = Cmd2ArgumentParser()
    login_parser.add_argument('-u', '--username')
    login_parser.add_argument('-p', '--password')

    # Logout
    logout_parser = Cmd2ArgumentParser()

    # Change Username
    change_username_parser = Cmd2ArgumentParser()
    change_username_parser.add_argument('-n','--new_username')

    # Change Password
    change_password_parser = Cmd2ArgumentParser()
    change_password_parser.add_argument('-p', '--new_password')

    # Delete account
    delete_account_parser = Cmd2ArgumentParser()

    # ADMIN

    # Delete Accounts
    admin_delete_account_parser = Cmd2ArgumentParser()
    admin_delete_account_parser.add_argument('-id','--user_id')

    # Admin Change Usernames
    admin_change_username_parser = Cmd2ArgumentParser()
    admin_change_username_parser.add_argument('-id', '--user_id')
    admin_change_username_parser.add_argument('-u', '--new_username')

    # Admin Change Password
    admin_change_password_parser = cmd2.Cmd2ArgumentParser()
    admin_change_password_parser.add_argument('-id', '--user_id')
    admin_change_password_parser.add_argument('-p', '--new_password')

    # Admin List Blockchains
    admin_list_blockchains_of_user_parser = cmd2.Cmd2ArgumentParser()
    admin_list_blockchains_of_user_parser.add_argument('-id', '--user_id')

    # Admin List Users
    admin_list_users_parser = cmd2.Cmd2ArgumentParser()

    # API

    # Generate API Key
    generate_key_parser = Cmd2ArgumentParser()
    generate_key_parser.add_argument('-n', '--api_name')

    # Display API Keys
    display_api_keys_parser = Cmd2ArgumentParser()

    # Revoke API Key
    revoke_api_key_parser = Cmd2ArgumentParser()
    revoke_api_key_parser.add_argument('-n','--api_name')

    # Show
    show_parser = Cmd2ArgumentParser()

    # Change address
    address_parser = Cmd2ArgumentParser()
    address_parser.add_argument('-n', '--new_address', choices=['https://blockchain-security-system.ue.r.appspot.com',
                                                                'http://127.0.0.1:5000'])
    argcomplete.autocomplete(address_parser)

    # Change key (Temporary)
    key_parser = Cmd2ArgumentParser()
    key_parser.add_argument('-n', '--new_key')

    def deselect(self):
        self.selected_blockchain = ""
        self.update_prompt()

    @cmd2.with_argparser(select_parser)
    def do_select(self, args):
        """
        Select a blockchain using the provided code.

        Usage:
        select_blockchain -bn <blockchain_name>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/select_blockchain'

        payload = json.dumps({
            'blockchain_name': args.blockchain_name
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()

            selected = return_selected(response.text)
            print(f'Blockchain "{selected}" has been selected.')
            self.selected_blockchain = selected
            self.update_prompt()
            print()
        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(deselect_parser)
    def do_deselect(self, args):
        if self.selected_blockchain == "":
            print("No blockchains currently selected.")
            print()
        else:
            print(f'Blockchain {self.selected_blockchain} has been deselected.')
            print()
            self.deselect()
            self.update_prompt()

    @cmd2.with_argparser(create_parser)
    def do_create(self, args):
        """
        Create a new blockchain using the provided code.

        Usage:
        create <blockchain_name> <blockchain_type> <blockchain_password>
        """
        if not args.blockchain_name:
            print("Error: Blockchain name cannot be empty.")
            print("Usage: create -bn <blockchain_name> -type <blockchain_type> -pass <blockchain_password>")
            print()
            return

        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/create_blockchain'

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'is_public': args.is_public,
            'blockchain_password': args.blockchain_password
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()
        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(delete_parser)
    def do_delete_blockchain(self, args):
        """
        Delete an existing blockchain using the provided code.

        Usage:
        delete_blockchain -bn <blockchain_name>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/delete_blockchain'

        payload = json.dumps({
            'blockchain_name': args.blockchain_name
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.delete(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()
        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(store_parser)
    def do_store(self, args):
        """
        Store hashed data in the blockchain using the provided code.

        Usage:
        store -bn <blockchain_name> -data <data> -ref <reference>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/store_in_blockchain'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'data': args.data,
            'reference': args.reference
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(store_hashed_parser)
    def do_store_hash(self, args):
        """
        Store hashed data in the blockchain using the provided code.

        Usage:
        store_hash -bn <blockchain_name> -data <data> -ref <reference>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/store_in_blockchain_hashed'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'data': args.data,
            'reference': args.reference
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(search_parser)
    def do_search_data(self, args):
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/search_in_blockchain'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'criteria': args.criteria,
            'value': args.value
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()

            # Parse the JSON response
            json_response = json.loads(response.text)

            # Display the message
            print(json_response.get('message', ''))

            # Display each result on a new line
            for result in json_response.get('results', []):
                print(f"[{result['id']}] {result['data']}")

            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print(return_message(response.text))
            print()

    @cmd2.with_argparser(display_search_results_parser)
    def do_display_search_results(self, args):
        """
        Display search results.

        Usage:
        display_search_results
        """
        api_key = self.api_key
        url = f'{self.server_url}/display_search_results'

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            print(return_result(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    def do_clear_search_results(self, args):
        """
        Clear search results.

        Usage:
        clear_search_results
        """
        api_key = self.api_key
        url = f'{self.server_url}/clear_search_result'

        payload = ""

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(get_search_index_parser)
    def do_get_search_index(self, args):
        """
        Get search index.

        Usage:
        get_search_index --index <index>
        """
        url = f'{self.server_url}/get_search_index'

        data = {
            'index': args.index
        }

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.get(url, headers=headers, data=json.dumps(data))
            response.raise_for_status()
            print(return_result(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(str(e)))
            print()

    @cmd2.with_argparser(verify_parser)
    def do_verify_blockchain(self, args):
        """
        Verify the integrity of the 'nicochain' blockchain using the provided code.
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/verify_blockchain'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            "blockchain_name": args.blockchain_name
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.request("GET", url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(update_block_by_id_parser)
    def do_update_by_id(self, args):
        """
        Update a block in the blockchain by ID using the provided code.

        Usage:
        update_by_id -bn <blockchain_name> -id <block_id> -n <new_data>
        """
        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        if not args.blockchain_name or not args.block_id or not args.new_data:
            print("Error: Blockchain name, block ID, and new data are required.")
            print("Usage: update_block_by_id -bn <blockchain_name> -id <block_id> -n <new_data>")
            print()
            return

        update_block_url = f'{self.server_url}/update_block_by_id'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        headers = {
            'apikey': self.api_key,
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        payload = json.dumps({
            "blockchain_name": args.blockchain_name,
            "block_id": args.block_id,
            "new_data": args.new_data
        })

        try:
            response = requests.put(update_block_url, headers=headers, data=payload)
            response.raise_for_status()

            if response.status_code == 200:
                print(return_message(response.text))
                print()
            elif response.status_code == 404:
                print(return_error(response.text))
                print()
            else:
                response.raise_for_status()

            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(update_parser)
    def do_update_block(self, args):
        """
        Update a block in the blockchain by criteria using the provided code.

        Usage:
        update_block -bn <blockchain_name> -c <criteria> -v <value> -n <new_data>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/update_block_by_criteria'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'criteria': args.criteria,
            'value': args.value,
            'new_data': args.new_data
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.put(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(update_block_by_id_parser)
    def do_update_by_id_hashed(self, args):
        """
        Update a block in the blockchain by ID as Hash using the provided code.

        Usage:
        update_block_by_id_hashed -bn <blockchain_name> -id <block_id> -n <new_data>
        """
        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        if not args.blockchain_name or not args.block_id or not args.new_data:
            print("Error: Blockchain name, block ID, and new data are required.")
            print("Usage: update_block_by_id_as_hash -bn <blockchain_name> -id <block_id> -n <new_data>")
            print()
            return

        update_block_by_id_as_hash_url = f'{self.server_url}/update_block_by_id_as_hash'

        headers = {
            'apikey': self.api_key,
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        payload = json.dumps({
            "blockchain_name": args.blockchain_name,
            "block_id": args.block_id,
            "new_data": args.new_data
        })

        try:
            response = requests.put(update_block_by_id_as_hash_url, headers=headers, data=payload)
            response.raise_for_status()

            if response.status_code == 200:
                print(return_message(response.text))
                print()
            elif response.status_code == 404:
                print(return_error(response.text))
                print()
            else:
                response.raise_for_status()

            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(update_parser)
    def do_update_block_hashed(self, args):
        """
        Update a block in the blockchain by criteria as Hash using the provided code.

        Usage:
        update_as_hash -bn <blockchain_name> -c <criteria> -v <value> -n <new_data>
        """
        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        if not args.blockchain_name or not args.criteria or not args.value or not args.new_data:
            print("Error: Blockchain name, criteria, value, and new data are required.")
            print("Usage: update_block_by_criteria_as_hash -bn <blockchain_name> -c <criteria> -v <value> -n <new_data>")
            print()
            return

        update_block_by_criteria_as_hash_url = f'{self.server_url}/update_block_by_criteria_as_hash'

        headers = {
            'apikey': self.api_key,
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        payload = json.dumps({
            "blockchain_name": args.blockchain_name,
            "criteria": args.criteria,
            "value": args.value,
            "new_data": args.new_data
        })

        try:
            response = requests.put(update_block_by_criteria_as_hash_url, headers=headers, data=payload)
            response.raise_for_status()

            if response.status_code == 200:
                print(return_message(response.text))
                print()
            elif response.status_code == 404:
                print(return_error(response.text))
                print()
            else:
                response.raise_for_status()

            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(delete_reference_parser)
    def do_delete_block(self, args):
        """
        Delete a reference in the blockchain by ID using the provided code.

        Usage:
        delete_block -bn <blockchain_name> -id <block_id>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/delete_reference_by_id'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'block_id': args.block_id
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.delete(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(delete_reference_by_criteria_parser)
    def do_delete_blocks_by_criteria(self, args):
        """
        Delete a reference in the blockchain by criteria using the provided code.

        Usage:
        delete_reference_by_criteria -bn <blockchain_name> -c <criteria> -v <value>
        """
        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        if not args.blockchain_name or not args.criteria or not args.value:
            print("Error: Blockchain name, criteria, and value are required.")
            print("Usage: delete_reference_by_criteria -bn <blockchain_name> -c <criteria> -v <value>")
            print()
            return

        delete_reference_url = f'{self.server_url}/delete_reference_by_criteria'

        headers = {
            'apikey': self.api_key,
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        payload = json.dumps({
            "blockchain_name": args.blockchain_name,
            "criteria": args.criteria,
            "value": args.value
        })

        try:
            response = requests.delete(delete_reference_url, headers=headers, data=payload)
            response.raise_for_status()

            if response.status_code == 200:
                print(return_message(response.text))
                print()
            elif response.status_code == 404:
                print(return_error(response.text))
                print()
            else:
                response.raise_for_status()

            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(list_blockchains_parser)
    def do_list(self, args):
        """
        List all blockchains.

        Usage:
        list
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/list_blockchains'

        headers = {
            'apikey': api_key,
            'Cookie': self.session_cookie,
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            blockchains = response.json().get('blockchains', [])

            if blockchains:
                print("Blockchains:")
                for blockchain in blockchains:
                    print(f"- {blockchain}")

            else:
                print("No blockchains found.")

            print()
        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(list_references_parser)
    def do_list_r(self, args):
        """
        List references for a specific blockchain.

        Usage:
        list_references -bn <blockchain_name>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/list_references'

        if args.blockchain_name is None:
            args.blockchain_name = self.selected_blockchain

        payload = json.dumps({
            'blockchain_name': args.blockchain_name
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.get(url, headers=headers, data=payload)
            if response.status_code == 200:
                references = response.json().get('references', [])

                seen_references = set()
                if references:
                    print("References:")
                    for reference in references:
                        if reference not in seen_references:
                            print(f"- {reference}")
                            seen_references.add(reference)
                else:
                    print("No references found for the specified blockchain.")
            elif response.status_code == 404:
                print(return_error(response.text))
                print()
            else:
                response.raise_for_status()

            print()
        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(address_parser)
    def do_set_add(self, args):
        print()
        """
        Changes the address of the API

        Usage:
        change_add -n <new_address>
        """
        if args is None or not args.new_address:
            print("Error: New address cannot be empty.")
            print()
            return

        print("Address updated successfully.")
        print()
        self.api_address = args.new_address

    @cmd2.with_argparser(key_parser)
    def do_set_key(self, args):
        print()
        """
        Changes the key of the API

        Usage:
        change_add -n <new_key>
        """
        if args is None or not args.new_key:
            print("Error: New key cannot be empty.")
            print()
            return
        print("Key updated succesfully.")
        print()
        self.api_key = args.new_key

    @cmd2.with_argparser(address_parser)
    def do_show_add(self, args):
        print()
        """
        Shows the address of the API

        Usage:
        show_add
        """
        print("Address: ", self.api_address)
        print()

    @cmd2.with_argparser(key_parser)
    def do_show_key(self, args):
        print()
        """
        Show the key of the API

        Usage:
        show_key
        """
        print("Key: ", self.api_key)
        print()

    @cmd2.with_argparser(address_parser)
    def do_show_session(self, args):
        print()
        """
        Shows the session

        Usage:
        show_session
        """
        print("Session: ", self.session_cookie)
        print()


    # USER
    @cmd2.with_argparser(create_user_parser)
    def do_create_user(self, args):
        """
        Create a new user using the provided code.

        Usage:
        create_user -u <username> -p <password> -a <is_admin>
        """
        if not args.username or not args.password or args.is_admin is None:
            print("Error: Username, password, and is_admin are required.")
            print("Usage: create_user -u <username> -p <password> -a <is_admin>")
            print()
            return

        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/create_user'

        payload = {
            'username': args.username,
            'password': args.password,
            'is_admin': args.is_admin
        }

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie,
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()
        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(register_parser)
    def do_register(self, args):
        """
        Register a new user using the provided code.

        Usage:
        register -u <username> -p <password>
        """
        url = f'{self.server_url}/register'

        payload = json.dumps({
            'username': args.username,
            'password': args.password
        })

        headers = {
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(login_parser)
    def do_login(self, args):
        """
        Log in with the provided username and password.

        Usage:
        login -u <username> -p <password>
        """

        if not args.username or not args.password:
            print("Error: Username and password are required.")
            print("Usage: login -u <username> -p <password>")
            print()
            return

        url = f'{self.server_url}/login'

        payload = json.dumps({
            'username': args.username,
            'password': args.password
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()

            # Extract the session value from the Set-Cookie header
            set_cookie_header = response.headers.get('Set-Cookie')
            session_value = None

            if set_cookie_header:
                # Parse the Set-Cookie header to extract the session value
                cookies = [cookie.strip() for cookie in set_cookie_header.split(';')]
                for cookie in cookies:
                    if cookie.startswith('session='):
                        session_value = cookie.split('=')[1]
                        break

            self.session_cookie = "session=" + session_value

            if "Login successful" in response.text:
                print(return_message(response.text))
                print()

                self.username = args.username
                self.user_type = return_usertype(response.text)
                self.update_prompt()
            else:
                print(return_error(response.text))
                print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(logout_parser)
    def do_logout(self, args):
        """
        Log out the user with the provided username and password.

        Usage:
        logout -u <username> -p <password>
        """
        url = f'{self.server_url}/logout'

        payload = ""
        headers = {
            'Cookie' : self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()

            print(return_message(response.text))

            self.session_cookie = ""
            print()

            self.username = ""
            self.user_type = ""
            self.deselect()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(change_username_parser)
    def do_change_username(self, args):
        """
        Change the username.

        Usage:
        change_username <new_username>
        """
        url = f'{self.server_url}/change_username'

        payload = {
            "new_username": args.new_username
        }

        headers = {
            'Cookie' : self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

            # Extract the session value from the Set-Cookie header
            set_cookie_header = response.headers.get('Set-Cookie')
            session_value = None

            if set_cookie_header:
                # Parse the Set-Cookie header to extract the session value
                cookies = [cookie.strip() for cookie in set_cookie_header.split(';')]
                for cookie in cookies:
                    if cookie.startswith('session='):
                        session_value = cookie.split('=')[1]
                        break

            self.session_cookie = "session=" + session_value

            self.username = args.new_username
            self.update_prompt()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(change_password_parser)
    def do_change_password(self, args):
        """
        Change the password for the logged-in user.

        Usage:1
        change_password -p <new_password>
        """
        url = f'{self.server_url}/change_password'

        payload = {
            'new_password': args.new_password
        }

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(delete_account_parser)
    def do_delete_account(self, args):
        """
        Delete a user account.

        Usage:
        delete_account
        """
        url = f'{self.server_url}/delete_account'

        payload = {}
        headers = {
            'Cookie' : self.session_cookie
        }

        try:
            response = requests.request("DELETE", url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()
            print(return_message(response.text))
            print()

            # Clear the session cookie
            self.session_cookie = ""

            self.username = ""
            self.user_type = ""
            self.update_prompt()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    # ADMIN
    @cmd2.with_argparser(admin_delete_account_parser)
    def do_admin_delete_account(self, args):
        """
        Admin delete a user account.

        Usage:
        admin_delete_account <user_id>
        """
        url = f'{self.server_url}/admin_delete_account'

        payload = {
            'user_id': args.user_id
        }
        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.delete(url, headers=headers, json=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

            self.session_cookie = ""

            # Extract the session value from the Set-Cookie header
            set_cookie_header = response.headers.get('Set-Cookie')
            session_value = None

            if set_cookie_header:
                # Parse the Set-Cookie header to extract the session value
                cookies = [cookie.strip() for cookie in set_cookie_header.split(';')]
                for cookie in cookies:
                    if cookie.startswith('session='):
                        session_value = cookie.split('=')[1]
                        break

            self.session_cookie = "session=" + session_value

            self.username = ""
            self.user_type = ""
            self.update_prompt()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    # NO UPDATE USERNAME FOR ADMIN YET
    @cmd2.with_argparser(admin_change_username_parser)
    def do_admin_change_username(self, args):
        """
        Change the username of a user account by user_id.

        Usage:
        admin_change_username -u <user_id> -n <new_username>
        """
        url = f'{self.server_url}/admin_change_username'

        payload = {
            'user_id': args.user_id,
            'new_username': args.new_username
        }

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()


        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(admin_change_password_parser)
    def do_admin_change_password(self, args):
        """
        Admin change password.

        Usage:
        admin_change_password -id <user_id> -p <new_password>
        """
        url = f'{self.server_url}/admin_change_password'

        payload = json.dumps({
            "user_id": args.user_id,
            "new_password": args.new_password
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_message(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(admin_list_blockchains_of_user_parser)
    def do_admin_list_blockchains_of_user(self, args):
        """
        Admin list blockchains of a user.

        Usage:
        admin_list_blockchains_of_user -id <user_id>
        """
        url = f'{self.server_url}/admin_list_blockchains_of_user'
        payload = json.dumps({
            "user_id": args.user_id
        })

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.get(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_blockchains(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    @cmd2.with_argparser(admin_list_users_parser)
    def do_admin_list_users(self, args):
        """
        Admin list users.

        Usage:
        admin_list_users --user_id <user_id>
        """
        url = f'{self.server_url}/admin_list_users'

        payload = ""

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.get(url, headers=headers, data=payload)
            response.raise_for_status()
            print(return_users(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    #API
    @cmd2.with_argparser(generate_key_parser)
    def do_apikey_gen(self, args):
        """
        Generate a new API key with a specified name using the provided code.

        Usage:
        apikey_gen -n <api_name>
        """

        api_key_url = f'{self.server_url}/generate_api_key'
        if args.api_name is None:
            args.api_name = 'Secret Key'

        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        payload = json.dumps({
            "api_name": args.api_name
        })

        try:
            response = requests.post(api_key_url, headers=headers, data=payload)
            response.raise_for_status()
            api_key = response.json().get('api_key', '')



            if api_key:
                print(f"Generated API Key for {args.api_name}: {api_key}")
            else:
                print("Error: Unable to retrieve the generated API Key.")
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print()

    def do_display_keys(self, args):
        """
        Display API keys.

        Usage:
        display_api_keys
        """
        url = f'{self.server_url}/display_api_keys'

        payload = ""
        headers = {
            'Cookie': self.session_cookie
        }

        try:
            response = requests.get(url, headers=headers, data=payload)
            response.raise_for_status()

            print(response.text)

        except requests.RequestException as e:
            print(return_error(response.text))

    @cmd2.with_argparser(revoke_api_key_parser)
    def do_revoke_key(self, args):
        """
        Revoke an API key.

        Usage:
        revoke_api_key -n <api_name>
        """
        url = f'{self.server_url}/revoke_api_key'

        payload = json.dumps({
            "api_name": args.api_name
        })
        headers = {
            'Content-Type': 'application/json',
            'Cookie': self.session_cookie
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()

            print(return_message(response.text))

        except requests.RequestException as e:
            print(return_error(response.text))

    def get_base_url(self, api_address):
        print()
        return api_address

    def get_api_key(self, api_key):
        print()
        return api_key

    available_commands = [
        "BLOCKCHAIN COMMANDS",
        "deselect\t\t\tDeselect the currently selected blockchain.",
        "select\t\t\t\tSelect a specific blockchain for operations.",
        "create\t\t\t\tCreate a new blockchain with the specified name, type, and password.",
        "delete_blockchain\t\tDelete an existing blockchain by providing its name.",
        "verify_blockchain\t\tVerify the integrity of the selected blockchain.",
        "",
        "STORING DATA TO BLOCKCHAIN",
        "store\t\t\t\tStore data in the selected blockchain with the specified data and reference.",
        "store_hash\t\t\tStore hashed data in the selected blockchain with the specified data and reference.",
        "",
        "SEARCH BLOCK COMMANDS",
        "search_data\t\t\tSearch for data in the selected blockchain using the specified criteria and value.",
        "display_search_results\t\tDisplay the results of the last search operation.",
        "clear_search_results\t\tClear the results of the last search operation",
        "get_search_index\t\tGet detailed information about a specific result from the last search.",
        "",
        "UPDATE BLOCK COMMANDS",
        "update_by_id\t\t\tUpdate a block in the selected blockchain by providing the block ID and new data.",
        "update_by_id_hashed\t\tUpdate a block in the selected blockchain as hash by providing the block ID and new data.",
        "update_block\t\t\tUpdate a block in the selected blockchain by providing criteria, value, and new data.",
        "update_block_hashed\t\tUpdate a block in the selected blockchain by criteria as Hash.",
        "",
        "DELETE COMMANDS",
        "delete_block\t\t\tDelete a reference in the selected blockchain by providing the block ID.",
        "delete_blocks_by_criteria\tDelete references in the selected blockchain based on criteria.",
        "",
        "LIST COMMANDS",
        "list\t\t\t\tList all available blockchains.",
        "list_r\t\t\t\tList references for the selected blockchain.",
        "",
        "API COMMANDS",
        "apikey_gen\t\t\tGenerate a new API key with a specified name.",
        "set_key\t\t\t\tSet the API key for the current session.",
        "show_key\t\t\tShow the current API key.",
        "revoke_key\t\t\tRevoke the current API key.",
        "",
        "ACCOUNT COMMANDS",
        "register\t\t\tRegister a new user with the specified username and password.",
        "login\t\t\t\tLog in with the provided username and password.",
        "logout\t\t\t\tLog out the current user.",
        "change_username\t\t\tChange the username for the current user.",
        "change_password\t\t\tChange the password for the current user.",
        "delete_account\t\t\tDelete the account of the current user.",
        "",
        "Additionally, you can type \"<command> -h\" for more details on the command.",
        ""
    ]
    # Regular User Commands

    # Admin User Commands
    available_admin_commands = [
        "create_user\t\t\tCreate a new user with the specified username, password, and admin status.",
        "admin_delete_account\t\tDelete the account of a specific user.",
        "admin_change_username\t\tChange the username of a specific user.",
        "admin_change_password\t\tChange the password of a specific user.",
        "admin_list_blockchains_of_user\tList the blockchains owned by a specific user.",
        "admin_list_users\t\tList all registered users.",
        ""
    ]

    def do_help(self, arg):
        print()
        """
        Display information about available commands.
        Usage: help [command]
        """
        if arg:
            super().do_help(arg)
        else:
            print("\nAvailable Commands:")
            for cmd in self.available_commands:
                print(f"{cmd}")

    def do_admin_help(self,arg):
        print()
        """
        Display information about available admin commands.
        Usage: help [command]
        """

        if arg:
            super().do_admin_help(arg)
        else:
            print("\nAvailable ADMIN Commands:")
            for cmd in self.available_admin_commands:
                print(f"{cmd}")


if __name__ == '__main__':
    api_key = ''
    api_address = "https://127.0.0.1:5000"
    print("- Blockchain Security System v1.0 -")
    print("Address: ", api_address)
    # print("Key: ", api_key)
    print()
    print("Type \"help\" for commands")

    blockchain_cmd = BlockchainCmd(api_key)
    blockchain_cmd.cmdloop()
