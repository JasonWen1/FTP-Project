from conf import settings
import json
import os
import configparser
import hashlib
import subprocess
import time
import logging
import shutil
import socketserver


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


def get_logger(name=None):
    """Configure and return a logger."""
    log_directory = os.path.join(os.path.dirname(__file__), '..', 'log')
    os.makedirs(log_directory, exist_ok=True)
    log_file_path = os.path.join(log_directory, 'ftp_server.log')

    # Set up a specific logger with our desired output level
    logger = logging.getLogger(name if name else 'FTPServer')
    logger.setLevel(logging.INFO)

    # Check if the logger already has handlers configured
    if not logger.handlers:
        # Add the log message handler to the logger
        handler = logging.FileHandler(log_file_path)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


class FTPServer(socketserver.BaseRequestHandler):
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

    def __init__(self, request, client_address, server):
        """
        Initializes the FTPServer object with utilities and configurations.

        Parameters:
        - utils: A utility object providing additional functionalities (not detailed here).
        """
        '''
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((settings.HOST, settings.PORT))
        self.sock.listen(settings.MAX_SOCKET_LISTEN)
        '''

        # Default logger before authentication
        self.logger = logging.getLogger('FTPServer')
        self.accounts = self.load_accounts()
        self.user = None
        self.user_current_dir = None
        super().__init__(request, client_address, server)

    '''
    def run(self):
        """
        Starts the FTP server to listen for incoming connections continuously.
        On accepting a connection, it handles the session in a dedicated method.
        """
        print('FTP server is running on %s:%s' %
              (settings.HOST, settings.PORT))
        self.logger.info('FTP server is running.')

        while True:
            #self.conn, self.addr = self.sock.accept()
            self.logger.info(f'Connected from: {self.addr}')
            try:
                self.handle()
            except Exception as e:
                self.logger.exception(
                    'Error with client, closing connection: %s', e)
                self.conn.close()
    '''

    def handle(self):
        """
        Handles the incoming data on a connected socket. Processes each message according to its action type.
        """

        print('Connected from: ', self.client_address)
        self.logger.info('FTP server is running.')
        try:
            while True:
                raw_data = self.request.recv(1024).strip()
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
        except Exception as e:
            self.logger.exception(
                'Error with client, closing connection: %s', e)

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
                # if not os.path.exists(self.user_current_dir):
                os.makedirs(self.user_current_dir, exist_ok=True)
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

        self.request.send(data_in_bytes)
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
                    self.request.send(line)
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
                data = self.request.recv(file_size - received_size)
            else:
                data = self.request.recv(self.RECV_SIZE)
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
        self.request.send(cmd_result)
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
        # Setup local logger for this function
        logger = logging.getLogger('CreateUserDirectly')
        log_directory = os.path.join(os.path.dirname(__file__), '..', 'log')
        # Ensure the log directory exists
        os.makedirs(log_directory, exist_ok=True)
        log_file_path = os.path.join(log_directory, 'ftp_server.log')

        # Setup file handler with a specific formatter
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        # Attach handler to the logger
        logger.addHandler(file_handler)
        logger.setLevel(logging.INFO)

        # Clear any previous handlers if they exist to avoid duplicate logs
        if logger.hasHandlers():
            logger.handlers.clear()

        logger.addHandler(file_handler)

        username = data.get('username')
        password = hashlib.md5(data.get('password').encode()).hexdigest()
        if username not in self.accounts:
            self.accounts[username] = {'password': password}
            os.makedirs(os.path.join(
                settings.USER_BASE_DIR, username), exist_ok=True)
            self.save_accounts()
            self.send_response(200, status_msg="User created successfully.")
            logger.info("User created successfully. Username: %s", username)
        else:
            self.send_response(400, status_msg="Username already exists.")
            logger.warning(
                f"Failed to create user: Username {username} already exists.")

        # Detach the file handler after logging to avoid interference with other loggers
        logger.removeHandler(file_handler)
        file_handler.close()

    @staticmethod
    def create_user_directly(username, password):
        """
        Directly creates a user from the command line input.
        This function is used for administrative purposes to add users without client interaction.

        Args:
        username (str): Desired username for the new account.
        password (str): Raw password which will be hashed before storage.
        """
        logger = get_logger("StaticMethod")
        accounts = FTPServer.load_accounts_static()

        # Check if the username already exists
        if username in accounts:
            logger.error(
                "Attempt to create a user that already exists: Username: %s", username)
            print("Error: Username already exists.")
            return

        # Hash the password
        password_hashed = hashlib.md5(password.encode()).hexdigest()

        # Add the user to the accounts dictionary
        accounts[username] = {'password': password_hashed}

        # Create the user directory
        user_directory = os.path.join(settings.USER_BASE_DIR, username)
        os.makedirs(user_directory, exist_ok=True)

        # Save the updated accounts information
        FTPServer.save_accounts_static(accounts)

        # Log and print success message
        logger.info("User created successfully. Username: %s", username)
        print(f"User created successfully. Username: {username}")

    @staticmethod
    def load_accounts_static():
        """
        Loads the account information from a configuration file.
        This function populates the server's accounts dictionary with user information.

        Returns:
        accounts (dict): A dictionary of accounts with usernames as keys.
        """
        logger = get_logger("StaticMethod")
        config = configparser.ConfigParser()
        # Construct the path to the configuration file
        config_path = os.path.join(os.path.dirname(
            __file__), '..', 'conf', 'accounts.ini')
        config.read(config_path)
        accounts = {section: dict(config.items(section))
                    for section in config.sections()}
        logger.info("Loading accounts from static method")
        return accounts

    @staticmethod
    def save_accounts_static(accounts):
        """Static method to save accounts."""
        logger = get_logger("StaticMethod")
        config = configparser.ConfigParser()
        account_file_path = os.path.join(os.path.dirname(
            __file__), '..', 'conf', 'accounts.ini')
        config.read(account_file_path)

        for username, details in accounts.items():
            if not config.has_section(username):
                config.add_section(username)
            for key, value in details.items():
                config.set(username, key, value)

        with open(account_file_path, 'w') as configfile:
            config.write(configfile)
        logger.info("Accounts saved by static method")

    def _rmdir(self, data):
        """
        Sends a request to remove an empty directory on the server.
        The method checks if the directory is empty before removal and updates the local current directory if necessary.

        Args:
        cmd_list (list): A list containing the directory name to be removed.

        The method sends a request to remove an empty directory and updates the current working directory based on the server's response.
        It handles various responses such as successful removal, failure due to non-empty directory, or other errors.
        """
        dir_name = data.get('dir_name')
        full_path = os.path.join(self.user_current_dir, dir_name)
        if os.path.isdir(full_path):
            if not os.listdir(full_path):  # Check if the directory is empty
                os.rmdir(full_path)
                # Log directory removal
                self.logger.info(f"Directory removed: {dir_name}")

                # Check if the current working directory is within the directory being removed
                if self.user_current_dir.startswith(full_path):
                    # Move the current directory up one level
                    self.user_current_dir = os.path.abspath(
                        os.path.join(full_path, os.pardir))
                self.send_response(
                    status_code=320, current_dir=self.user_current_dir)
            else:
                self.send_response(status_code=321)  # Directory is not empty
                self.logger.warning(
                    f"Failed to remove directory {dir_name}: Directory not empty")
        else:
            self.send_response(status_code=311)  # Directory does not exist
            self.logger.error(
                f"Failed to remove directory {dir_name}: Directory does not exist")

    def _rm(self, data):
        """
        Sends a request to remove a file on the server.
        This method checks command parameters for correctness before sending a delete request.

        Args:
        cmd_list (list): A list containing the filename to be deleted.

        The method sends a delete request to the server and processes the response,
        displaying an appropriate message based on whether the deletion was successful.
        """
        filename = data.get('filename')
        full_path = os.path.join(self.user_current_dir, filename)

        # Check if the file exists
        if not os.path.isfile(full_path):
            self.send_response(
                status_code=300, status_msg="File does not exist.")
            self.logger.error(
                f"File removal failed: {filename} does not exist")
            return

        # Attempt to remove the file
        try:
            os.remove(full_path)
            self.send_response(
                status_code=301, status_msg="File removed successfully.")
            self.logger.info(f"File removed: {filename}")
        except OSError as e:
            self.send_response(
                status_code=302, status_msg=f"Error removing file: {str(e)}")
            self.logger.error(f"Error removing file {filename}: {str(e)}")

    def _rm_rf(self, data):
        """
        Recursively remove a directory and all its contents with logging.

        Args:
        data (dict): A dictionary containing 'dir_name', the name of the directory to remove.
        """
        dir_name = data.get('dir_name')
        full_path = os.path.join(self.user_current_dir, dir_name)

        # Check if the directory exists
        if not os.path.exists(full_path):
            self.send_response(
                status_code=311, status_msg="Directory does not exist.")
            self.logger.warning(
                f"Attempted to remove non-existent directory: {dir_name}")
            return

        # Try to remove the directory and its contents
        try:
            shutil.rmtree(full_path)
            self.send_response(
                status_code=320, status_msg="Directory and all contents removed successfully.")
            self.logger.info(
                f"Successfully removed directory and its contents: {dir_name}")

        except Exception as e:
            self.send_response(
                status_code=322, status_msg=f"Failed to remove directory: {str(e)}")
            self.logger.error(
                f"Failed to remove directory {dir_name}: {str(e)}")
