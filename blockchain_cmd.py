import argparse
import cmd2
import requests
from cmd2 import Cmd2ArgumentParser
from requests import RequestException
import json
import argcomplete


class BlockchainCmd(cmd2.Cmd):
    def __init__(self, api_key):
        super().__init__()
        self.api_address = ""
        self.api_key = api_key
        self.server_url = 'http://127.0.0.1:5000'
        self.prompt = "> "

    # Create blockchain
    create_parser = Cmd2ArgumentParser()
    create_parser.add_argument('-bn', '--blockchain_name')
    create_parser.add_argument('-pub', '--isPublic', choices=['1','0'])
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

    # Delete
    delete_reference_parser = Cmd2ArgumentParser()
    delete_reference_parser.add_argument('-bn', '--blockchain_name')
    delete_reference_parser.add_argument('-id', '--block_id')

    # List Blockchains
    list_blockchains_parser = Cmd2ArgumentParser()

    # List References
    list_references_parser = Cmd2ArgumentParser()
    list_references_parser.add_argument('-bn', '--blockchain_name')

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
        create <blockchain_name> <isPublic> <blockchain_password>
        """
        if not args.blockchain_name:
            print("Error: Blockchain name cannot be empty.")
            print("Usage: create -bn <blockchain_name> -pub <isPublic> -pass <blockchain_password>")
            print()
            return

        api_key = self.api_key
        server_url = self.server_url

        url = f'{server_url}/create_blockchain'

        payload = json.dumps({
            'blockchain_name': args.blockchain_name,
            'isPublic': args.isPublic,
            'blockchain_password': args.blockchain_password
        })

        headers = {
            'Content-Type': 'application/json',
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()
        except requests.RequestException as e:
            print(f'Error: Failed to create blockchain. - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.delete(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()
        except requests.RequestException as e:
            print(f'Error: Failed to delete blockchain - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()

        except requests.RequestException as e:
            print(f'Error: Failed to store data in blockchain - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()

        except requests.RequestException as e:
            print(f'Error: Failed to store hashed data in blockchain - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.get(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()

        except requests.RequestException as e:
            print(f'Error: Failed to search in blockchain - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.request("GET", url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()

        except requests.RequestException as e:
            print(f'Error: Failed to verify blockchain - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.put(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()

        except requests.RequestException as e:
            print(f'Error: Failed to update block by criteria - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
        }

        try:
            response = requests.delete(url, headers=headers, data=payload)
            response.raise_for_status()
            print(response.text)
            print()

        except requests.RequestException as e:
            print(f'Error: Failed to delete reference by ID - Check your command - Try \"<command> -h\" for more info')
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
            'apikey': api_key
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
            print(f'Error: Failed to list blockchains - Check your command - Try \"<command> -h\" for more info')
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
                print(f'Error: Blockchain "{args.blockchain_name}" does not exist.')
            else:
                response.raise_for_status()

            print()
        except requests.RequestException as e:
            print(f'Error: Failed to list references - Check your command - Try \"<command> -h\" for more info')
            print()

    @cmd2.with_argparser(address_parser)
    def do_change_add(self, args):
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

        print("Address Changed Successfully.")
        print()
        self.api_address = args.new_address

    @cmd2.with_argparser(key_parser)
    def do_change_key(self, args):
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
        print("Key Changed Succesfully.")
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
        "delete_block \t\t\tDelete a reference in the blockchain by providing the blockchain name and block ID.",
        "list \t\t\t\tList all blockchains.",
        "list_references \t\tList references for a specific blockchain by providing its name.",
        "change_add \t\t\tChange the address of the API by providing a new address.",
        "change_key \t\t\tChange the key of the API by providing a new key.",
        "show_add \t\t\tShow the current address of the API.",
        "show_key \t\t\tShow the current key of the API.",
        "quit \t\t\t\tExit the application.",
        "",
        "Additionally, you can type \"<command> -h\" for more details on the command.",
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
                print(f"- {cmd}")

    def send_request(self, url, data=None, params=None):
        print()
        headers = {'apikey': self.api_key}
        try:
            if data:
                response = requests.post(url, json=data, headers=headers)
            elif params:
                response = requests.get(url, params=params, headers=headers)
            else:
                response = requests.delete(url, json=data, headers=headers)

            try:
                print(response.json())
                print()
            except ValueError:
                # If the response is not in JSON format, print the raw content
                print(response.content.decode('utf-8'))
                print()

        except requests.ConnectionError:
            print('Error: Could not connect to the Flask server.')
            print()


if __name__ == '__main__':
    api_key = 'doesntmatter'
    api_address = "https://127.0.0.1:5000"
    print("- Blockchain Security System -")
    print("Address: ", api_address)
    print("Key: ", api_key)
    print()
    print("Type \"help\" for commands")

    blockchain_cmd = BlockchainCmd(api_key)
    blockchain_cmd.cmdloop()
