from core import main


class Utils(object):
    """
    This class provides utilities for handling command line arguments to perform actions
    like starting the server and creating users directly from the command line.
    """

    def __init__(self, argv):
        """
        Initializes the Utils object with command line arguments.

        Args:
            argv (list): List of command line arguments.
        """
        self.argv = argv
        print(self.argv)
        self.is_valid()

    def is_valid(self):
        """
        Validates the command line arguments. Ensures that the necessary commands and
        parameters are provided. If not, it prints the usage information.
        """
        if len(self.argv) < 2:
            self.print_usage()
        cmd = self.argv[1]
        if not hasattr(self, cmd):
            self.print_usage()

    def print_usage(self):
        """
        Prints the usage information for the script and exits. This method is called if
        the input arguments are missing or incorrect.
        """
        usage = '''
        Usage:
            python server.py start            # Start the FTP server
            python server.py createuser       # Create a new user
        '''
        print(usage)
        exit(1)

    def execute(self):
        """
        Executes the command provided in the command line arguments.
        It dynamically selects the method to call based on the command name.
        """
        cmd = self.argv[1]
        func = getattr(self, cmd)
        func()

    def start(self):
        """
        Starts the FTP server. This method is called when the 'start' command is used.
        """
        print('start ftp server')
        server = main.FTPServer(self)
        server.run()

    def createuser(self):
        """
        Creates a new user. This method is called when the 'createuser' command is used
        along with a username and password. It ensures the correct number of arguments are provided.
        """
        if len(self.argv) != 4:
            print("Usage: python server.py createuser <username> <password>")
            exit(1)
        username, password = self.argv[2], self.argv[3]
        server = main.FTPServer(self)
        # Call a method to create a user, passing username and password
        server.create_user_directly(username, password)
