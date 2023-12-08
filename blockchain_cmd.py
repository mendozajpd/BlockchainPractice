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


def return_error(errormsg):
    json_response = json.loads(errormsg)
    response_txt = json_response.get('error', '')
    return response_txt


class BlockchainCmd(cmd2.Cmd):

    def __init__(self, api_key):
        super().__init__()
        self.api_address = ""
        self.api_key = api_key
        self.server_url = 'http://127.0.0.1:5000'
        self.prompt = "> "
        self.session_cookie = ""
        self.set_window_title("Blockchain Security System CLI")


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

    @cmd2.with_argparser(create_parser)
    def do_create(self, args):
        print()
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
        print()
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
        print()
        """
        Store hashed data in the blockchain using the provided code.

        Usage:
        store -bn <blockchain_name> -data <data> -ref <reference>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/store_in_blockchain'

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
        print()
        """
        Store hashed data in the blockchain using the provided code.

        Usage:
        store_hash -bn <blockchain_name> -data <data> -ref <reference>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/store_in_blockchain_hashed'

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
        print()
        """
        Search in the blockchain using the provided code.

        Usage:
        search_data -bn <blockchain_name> -c <criteria> -v <value>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/search_in_blockchain'

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
            response = requests.get(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print(return_result(response.text))
            print()

        except requests.RequestException as e:
            print(return_error(response.text))
            print(return_message(response.text))
            print()

    @cmd2.with_argparser(verify_parser)
    def do_verify_blockchain(self, args):
        print()
        """
        Verify the integrity of the 'nicochain' blockchain using the provided code.
        """
        blockchain_name = args.blockchain_name
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/verify_blockchain'

        payload = json.dumps({
            "blockchain_name": blockchain_name
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
        if not args.blockchain_name or not args.block_id or not args.new_data:
            print("Error: Blockchain name, block ID, and new data are required.")
            print("Usage: update_block_by_id -bn <blockchain_name> -id <block_id> -n <new_data>")
            print()
            return

        update_block_url = f'{self.server_url}/update_block_by_id'

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
        print()
        """
        Update a block in the blockchain by criteria using the provided code.

        Usage:
        update_block -bn <blockchain_name> -c <criteria> -v <value> -n <new_data>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/update_block_by_criteria'

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
        print()
        """
        Delete a reference in the blockchain by ID using the provided code.

        Usage:
        delete_block -bn <blockchain_name> -id <block_id>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/delete_reference_by_id'

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
    def do_delete_block_by_criteria(self, args):
        """
        Delete a reference in the blockchain by criteria using the provided code.

        Usage:
        delete_reference_by_criteria -bn <blockchain_name> -c <criteria> -v <value>
        """
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
        print()
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
        print()
        """
        List references for a specific blockchain.

        Usage:
        list_references -bn <blockchain_name>
        """
        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/list_references'

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
        if not args.api_name:
            print("Error: API name cannot be empty.")
            print("Usage: generate_key_with_name -n <api_name>")
            print()
            return

        api_key_url = f'{self.server_url}/generate_api_key'

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
        "create \t\t\tCreate a new blockchain with the specified name, type, and password.",
        "delete_blockchain \t\tDelete an existing blockchain by providing its name.",
        "store \t\t\tStore data in the blockchain with the specified name, data, and reference.",
        "store_hash \t\t\tStore hashed data in the blockchain with the specified name, data, and reference.",
        "search_data \t\t\tSearch for data in the blockchain using the specified criteria and value.",
        "verify_blockchain \t\tVerify the integrity of a blockchain by providing its name.",
        "update_block \t\t\tUpdate a block in the blockchain with the specified criteria, value, and new data.",
        "update_by_id \t\t\tUpdate a block in the blockchain by ID",
        "update_block_hashed \t\tUpdate a block in the blockchain by criteria as Hash.",
        "update_by_id_hashed \t\tUpdate a block in the blockchain by ID as Hash.",
        "delete_block \t\t\tDelete a reference in the blockchain by providing the blockchain name and block ID.",
        "delete_block_by_criteria \tDelete a reference in the blockchain by criteria.",
        "list \t\t\t\tList all blockchains.",
        "list_r \t\t\tList references for a specific blockchain by providing its name.",
        "change_add \t\t\tChange the address of the API by providing a new address.",
        "change_key \t\t\tChange the key of the API by providing a new key.",
        "show_add \t\t\tShow the current address of the API.",
        "show_key \t\t\tShow the current key of the API.",
        "quit \t\t\t\tExit the application.",
        "apikey_gen \t\t\tGenerate a new API key with a specified name.",
        "create_user \t\t\tCreate a new user with the specified username, password, and admin status.",
        "register \t\t\tRegister a new user with the specified username and password.",
        "login \t\t\tLog in with the provided username and password.",
        "logout \t\t\tLog out the user with the provided username and password.",
        "show_session \t\t\tShow the current session.",
        "",
        "Additionally, you can type \"<command> -h\" for more details on the command.",
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



if __name__ == '__main__':
    api_key = ''
    api_address = "https://127.0.0.1:5000"
    print("- Blockchain Security System v1.0-")
    print("Address: ", api_address)
    print("Key: ", api_key)
    print()
    print("Type \"help\" for commands")

    blockchain_cmd = BlockchainCmd(api_key)
    blockchain_cmd.cmdloop()
