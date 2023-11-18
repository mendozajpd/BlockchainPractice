import argparse
import cmd2
import requests
from cmd2 import Cmd2ArgumentParser
from requests import RequestException


class BlockchainCmd(cmd2.Cmd):
    def __init__(self, api_key):
        super().__init__()
        self.api_key = api_key
        self.server_url = 'http://127.0.0.1:5000'
        self.prompt = "> "

    dir_parser = Cmd2ArgumentParser()
    dir_parser.add_argument('-l', '--long', action='store_true', help="display in long format with one item per line")

    def do_create_blockchain(self, args):
        """Create a new blockchain."""
        blockchain_name, blockchain_type, blockchain_password = args.split()
        self.create_blockchain(blockchain_name, blockchain_type, blockchain_password)

    def do_delete_blockchain(self, args):
        """Delete an existing blockchain."""
        blockchain_name = args
        self.delete_blockchain(blockchain_name)

    def do_store_in_blockchain_hashed(self, args):
        """Store hashed data in the blockchain."""
        blockchain_name, data, reference = args.split()
        self.store_in_blockchain_hashed(blockchain_name, data, reference)

    def do_store_in_blockchain(self, args):
        """Store data in the blockchain."""
        blockchain_name, data, reference = args.split()
        self.store_in_blockchain(blockchain_name, data, reference)


    def do_search_blockchain(self, args):
        """Search in the blockchain."""
        blockchain_name, criteria, value = args.split()
        self.search_blockchain(blockchain_name, criteria, value)

    def create_blockchain(self, blockchain_name, blockchain_type, blockchain_password):
        endpoint = '/create_blockchain'
        url = self.get_base_url() + endpoint
        data = {
            'blockchain_name': blockchain_name,
            'blockchain_type': blockchain_type,
            'blockchain_password': blockchain_password
        }
        self.send_request(url, data)

    def delete_blockchain(self, blockchain_name):
        endpoint = '/delete_blockchain'
        url = self.get_base_url() + endpoint
        data = {'blockchain_name': blockchain_name}
        self.send_request(url, data)

    def store_in_blockchain_hashed(self, blockchain_name, data, reference):
        endpoint = '/store_in_blockchain_hashed'
        url = self.get_base_url() + endpoint
        data = {'blockchain_name': blockchain_name, 'data': data, 'reference': reference}
        self.send_request(url, data)

    def store_in_blockchain(self, blockchain_name, data, reference):
        endpoint = '/store_in_blockchain'
        url = self.get_base_url() + endpoint
        data = {'blockchain_name': blockchain_name, 'data': data, 'reference': reference}
        self.send_request(url, data)

    def do_verify_blockchain(self, args):
        """
        Verify the integrity of a blockchain.

        Usage:
        verify_blockchain <blockchain_name>

        Positional Arguments:
        blockchain_name  The name of the blockchain to verify.
        """

        if not args:
            print("Error: Missing blockchain_name argument")
            return

        blockchain_name = args[0]

        url = f'{self.server_url}/verify_blockchain'
        data = {'blockchain_name': blockchain_name}
        headers = {'apikey': self.api_key}

        try:
            response = requests.post(url, json=data, headers=headers)  # Use POST instead of GET
            response.raise_for_status()
            print(response.json())  # Assuming the response is in JSON format
        except RequestException as e:
            print(f'Error: Failed to verify blockchain - {e}')


    def search_blockchain(self, blockchain_name, criteria, value):
        endpoint = '/search_in_blockchain'
        url = self.get_base_url() + endpoint
        params = {'blockchain_name': blockchain_name, 'criteria': criteria, 'value': value}
        self.send_request(url, params=params)

    def get_base_url(self):
        return 'http://127.0.0.1:5000'

    def send_request(self, url, data=None, params=None):
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
            except ValueError:
                # If the response is not in JSON format, print the raw content
                print(response.content.decode('utf-8'))

        except requests.ConnectionError:
            print('Error: Could not connect to the Flask server.')


if __name__ == '__main__':
    api_key = 'doesntmatter'
    blockchain_cmd = BlockchainCmd(api_key)
    blockchain_cmd.cmdloop()
