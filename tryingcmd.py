import cmd2

class SimpleCLI(cmd2.Cmd):
    def __init__(self):
        super().__init__()

        # Set a custom prompt
        self.prompt = '> '

        # Set custom prefix characters
        self.prefix_chars = '!'

        # List of custom commands
        self.command_array = ['hello', 'world', 'exit']

    def do_hello(self, args):
        """Print 'Hello'"""
        print("Hello")

    def do_world(self, args):
        """Print 'World'"""
        print("World")

    def do_exit(self, args):
        """Exit the terminal"""
        print("Exiting...")
        return True

    # Override the default help command
    def do_help(self, args):
        """Custom help command"""
        if not args:
            # If no specific command is provided, list available commands
            print("Available commands:", ', '.join(self.command_array))
        else:
            # If a specific command is provided, call the help method of the cmd2.Cmd class
            super().do_help(args)

if __name__ == '__main__':
    SimpleCLI().cmdloop()