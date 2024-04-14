import socket
from conf import settings
import json
import os
import configparser
import hashlib
import subprocess
import time
import logging


def setup_logger(username):
    """
    Setup a logger specific to a username with a unique timestamp.
    This ensures each session's logs are kept separate for clarity and auditability.

    Parameters:
    - username (str): The username to associate with this logger instance.

    Returns:
    - logger (Logger): Configured logging.Logger object for the specified user.
    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_directory = os.path.join(os.path.dirname(__file__), '..', 'log')
    os.makedirs(log_directory, exist_ok=True)
    log_file_path = os.path.join(log_directory, f'{username}_{timestamp}.log')

    logger = logging.getLogger(f'{username}_{timestamp}')
    logger.setLevel(logging.INFO)

    # Prevent adding multiple handlers to the logger if it already has handlers.
    if not logger.handlers:
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(stream_handler)

    return logger


class FTPServer:
    """
    A class representing an FTP server which handles connections,
    authentications, and file operations with logging integrated.

    Attributes:
    - STATUS_CODE (dict): A dictionary mapping status codes to their descriptive messages.
    - MSG_SIZE (int): Standard size of messages sent to the client.
    - RECV_SIZE (int): Maximum size of data received at once from the client.
    """
    STATUS_CODE = {
        200: 'Passed authentication!',
        201: 'Incorrect username or password!',
        300: 'File not exist!',
        301: 'File exist!',
        302: 'Ready!',
        310: 'Directory changed!',
        311: 'Directory not exist!',
        320: 'Create directory successfully!',
        321: 'Directory already exist!',
        400: 'Error creating user'
    }

    MSG_SIZE = 1024
    RECV_SIZE = 8192

    def __init__(self, utils):
        """
        Initializes the FTPServer object with utilities and configurations.

        Parameters:
        - utils: A utility object providing additional functionalities (not detailed here).
        """
        self.utils = utils
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((settings.HOST, settings.PORT))
        self.sock.listen(settings.MAX_SOCKET_LISTEN)
        # Default logger before authentication
        self.logger = logging.getLogger('FTPServer')
        self.accounts = self.load_accounts()
        self.user = None
        self.user_current_dir = None

    def run(self):
        """
        Starts the FTP server to listen for incoming connections continuously.
        On accepting a connection, it handles the session in a dedicated method.
        """
        print('FTP server is running on %s:%s' %
              (settings.HOST, settings.PORT))
        self.logger.info('FTP server is running.')

        while True:
            self.conn, self.addr = self.sock.accept()
            self.logger.info(f'Connected from: {self.addr}')
            try:
                self.handle()
            except Exception as e:
                self.logger.exception(
                    'Error with client, closing connection: %s', e)
                self.conn.close()

    def handle(self):
        """
        Handles the incoming data on a connected socket. Processes each message according to its action type.
        """
        while True:
            raw_data = self.conn.recv(1024)
            if not raw_data:
                self.logger.info("Connection closed.")
                return
            print('----->', raw_data)

            try:
                data = json.loads(raw_data.decode("utf-8"))
                action_type = data.get('action_type')
                if action_type:
                    if hasattr(self, "_%s" % action_type):
                        func = getattr(self, "_%s" % action_type)
                        func(data)
                else:
                    print('invalid command')
                    self.logger.error("Invalid command received.")
            except json.JSONDecodeError as e:
                self.logger.error(f"Error decoding JSON: {str(e)}")

    def load_accounts(self):
        """
        Loads user accounts from a configuration file specified in the settings.

        Returns:
        - accounts (dict): A dictionary of loaded user accounts.
        """
        self.accounts = {}
        config = configparser.ConfigParser()
        config.read(settings.ACCOUNT_FILE)
        self.logger.info(f'Accounts loaded: {config.sections()}')
        return config

    def authenicate(self, username, password):
        """
        Authenticates a user using the provided username and password.

        Parameters:
        - username (str): The username to authenticate.
        - password (str): The password provided by the user for authentication.

        Returns:
        - bool: True if authentication is successful, otherwise False.
        """
        if username in self.accounts:
            _password = self.accounts[username]['password']
            print('password:', _password)
            # hash the password with md5
            password_md5 = hashlib.md5()
            password_md5.update(password.encode())
            print('password2:', password_md5.hexdigest())
            if _password == password_md5.hexdigest():
                print('passed authentication...')
                self.user = self.accounts[username]
                # set the home directory for the user
                self.user['home'] = os.path.join(
                    settings.USER_BASE_DIR, username)
                # set the current directory for the user
                self.user_current_dir = self.user['home']
                # Setup user-specific logger after authentication
                self.logger = setup_logger(username)
                self.logger.info(f'User {username} logged in successfully.')
                return True
            else:
                self.logger.warning(
                    f'Incorrect password for username {username}.')
        else:
            self.logger.warning(f'Username {username} not found.')
        return False

    def send_response(self, status_code, *args, **kwargs):
        '''send response to the client'''
        '''
        :param status_code: the status code
        :param args: other arguments
        :param kwargs: other keyword arguments, format: {'key': 'value', 'key2': 'value2'}
        '''
        data = kwargs
        data['status_code'] = status_code
        data['status_msg'] = self.STATUS_CODE[status_code]
        data['fill'] = ''
        data_in_bytes = json.dumps(data).encode('utf-8')

        if len(data_in_bytes) < self.MSG_SIZE:
            data['fill'] = data['fill'].zfill(
                self.MSG_SIZE - len(data_in_bytes))
            data_in_bytes = json.dumps(data).encode('utf-8')

        self.conn.send(data_in_bytes)
        self.logger.info(f'Response sent to client: {data}')

    '''authenticate the user'''

    def _auth(self, data):
        """
        Authenticate a user based on the provided username and password.

        Parameters:
            data (dict): A dictionary containing the username and password provided by the client.
        """
        print('auth ', data)
        if self.authenicate(data.get('username'), data.get('password')):
            print('pass auth')
            self.send_response(status_code=200)
        else:
            self.send_response(status_code=201)

    def _get(self, data):
        '''get the file name from the client and let the client download the file'''
        '''
        step1: get the file name from the client
        step2: check if the file exists
        step3: if the file exist, send the file to the client in chunks
        step4: if the file does not exist, send the response to the client
        '''
        filename = data.get('filename')
        full_path = os.path.join(self.user_current_dir, filename)
        if os.path.isfile(full_path):
            file_size = os.stat(full_path).st_size
            self.send_response(status_code=301, file_size=file_size)
            with open(full_path, 'rb') as f:
                for line in f:
                    self.conn.send(line)
            self.logger.info(
                f'File {filename} sent successfully to the client from {full_path}')
        else:
            self.send_response(status_code=300)
            self.logger.warning(
                f'File {filename} not found for download request.')

    def _put(self, data):
        '''
        put the file to the server
        1. get the file name and file size from the client
        2. check if the file exists
        (1) if the file exists, create a new file with file.timestamp  and then get the file from the client
        (2) if the file does not exist, get the file from the client
        '''
        filename = data.get('filename')
        full_path = os.path.join(self.user_current_dir, filename)

        if os.path.isfile(full_path):
            timestamp = str(time.time()).replace('.', '')
            timestamp = ''.join(filter(str.isdigit, timestamp))
            full_path = os.path.join(self.user_current_dir, '%s_%s%s' % (
                os.path.splitext(filename)[0], timestamp, os.path.splitext(filename)[1]))
        f = open(full_path, 'wb')
        file_size = data.get('file_size')
        received_size = 0
        while received_size < file_size:
            if file_size - received_size < self.RECV_SIZE:
                data = self.conn.recv(file_size - received_size)
            else:
                data = self.conn.recv(self.RECV_SIZE)
            received_size += len(data)
            f.write(data)
            print(received_size, file_size)
        else:
            self.logger.info(
                f'File {filename} uploaded successfully. Total size {received_size} bytes.')
            f.close()

    def _ls(self, data):
        '''list the files in the directory'''
        '''
        step1: get the file list
        step2: send the file list to the client
        '''
        # get the file list via the ls command and get the result from pipe
        cmd_obj = subprocess.Popen('ls %s' % self.user_current_dir,
                                   shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = cmd_obj.stdout.read()
        stderr = cmd_obj.stderr.read()

        cmd_result = stdout + stderr
        cmd_result_size = len(cmd_result)

        if cmd_result_size == 0:
            cmd_result = b'no files in the directory'
            cmd_result_size = len(cmd_result)

        self.send_response(status_code=302, cmd_result_size=cmd_result_size)
        self.conn.sendall(cmd_result)
        self.logger.info(
            f"List directory contents for {self.user_current_dir}: {cmd_result.decode()}")

    def _cd(self, data):
        '''change the directory'''
        '''use the target_dir to change the self.user_current_dir'''

        target_dir = data.get('target_dir')
        # get the full path of the target directory as an absolute path
        full_path = os.path.abspath(os.path.join(
            self.user_current_dir, target_dir))
        print('full_path: ', full_path)
        if os.path.isdir(full_path) and full_path.startswith(self.user['home']):
            self.user_current_dir = full_path
            relative_path = self.user_current_dir.replace(
                self.user['home'], '')
            self.logger.info(f"Changed directory to {relative_path}")
            self.send_response(status_code=310, current_dir=relative_path)
        else:
            self.send_response(status_code=311)
            self.logger.warning(f"Failed to change directory to {target_dir}")

    def _mkdir(self, data):
        '''create a directory'''
        '''create a directory in the self.user_current_dir'''
        dir_name = data.get('dir_name')
        full_path = os.path.join(self.user_current_dir, dir_name)
        if not os.path.exists(full_path):
            os.mkdir(full_path)
            self.send_response(status_code=320)
            self.logger.info(f"Directory created: {dir_name} at {full_path}")
        else:
            self.send_response(status_code=321)
            self.logger.warning(f"Directory already exists: {dir_name}")

    def load_accounts(self):
        """
        Loads the account information from a configuration file.
        This function populates the server's accounts dictionary with user information.

        Returns:
        accounts (dict): A dictionary of accounts with usernames as keys.
        """
        config = configparser.ConfigParser()
        # Construct the path to the configuration file
        config_path = os.path.join(os.path.dirname(
            __file__), '..', 'conf', 'accounts.ini')
        config.read(config_path)
        accounts = {section: dict(config.items(section))
                    for section in config.sections()}
        self.logger.info("Accounts loaded")
        return accounts

    def save_accounts(self):
        """
        Saves the updated account information back to the configuration file.
        This ensures that all account changes like new users or password changes are persisted.
        """
        config = configparser.ConfigParser()
        config.read(settings.ACCOUNT_FILE)  # Load existing data

        for username, details in self.accounts.items():
            if not config.has_section(username):
                config.add_section(username)  # Ensure the section exists
            for key, value in details.items():
                # Set or update key-value pair
                config.set(username, key, value)

        with open(settings.ACCOUNT_FILE, 'w') as configfile:
            config.write(configfile)
        self.logger.info("Accounts saved")

    def _create_user(self, data):
        """
        Handles creating a new user from client data.
        If the username does not exist, it creates a new user and saves the account.

        Args:
        data (dict): A dictionary containing the username and password.
        """
        username = data.get('username')
        password = hashlib.md5(data.get('password').encode()).hexdigest()
        if username not in self.accounts:
            self.accounts[username] = {'password': password}
            os.makedirs(os.path.join(
                settings.USER_BASE_DIR, username), exist_ok=True)
            self.save_accounts()
            self.send_response(200, status_msg="User created successfully.")
            self.logger.info(f"User created: {username}")
        else:
            self.send_response(400, status_msg="Username already exists.")
            self.logger.warning(
                f"Failed to create user: Username {username} already exists.")

    def create_user_directly(self, username, password):
        """
        Directly creates a user from the command line input.
        This function is used for administrative purposes to add users without client interaction.

        Args:
        username (str): Desired username for the new account.
        password (str): Raw password which will be hashed before storage.
        """
        # Setup local logger for this function
        logger = logging.getLogger('CreateUserDirectly')
        log_directory = os.path.join(os.path.dirname(__file__), '..', 'log')
        log_file_path = os.path.join(log_directory, 'ftp_server.log')

        if not logger.handlers:  # Avoid adding handlers multiple times
            file_handler = logging.FileHandler(log_file_path)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)
            logger.setLevel(logging.INFO)

        # Check if the username already exists
        if username in self.accounts:
            logger.error(
                "Attempt to create a user that already exists: Username: %s", username)
            print("Error: Username already exists.")
            return

        # Hash the password
        password_hashed = hashlib.md5(password.encode()).hexdigest()
        # Add the user to the accounts dictionary
        self.accounts[username] = {'password': password_hashed}

        # Create the user directory
        user_directory = os.path.join(settings.USER_BASE_DIR, username)
        os.makedirs(user_directory, exist_ok=True)

        # Save the updated accounts information
        self.save_accounts()

        # Log and print success message
        logger.info("User created successfully. Username: %s", username)
        print(f"User created successfully. Username: {username}")

        exit(0)
