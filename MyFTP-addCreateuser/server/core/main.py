import socket
from conf import settings
import json
import os
import configparser
import hashlib
import subprocess
import time


class FTPServer(object):
    '''FTP server class'''

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
        self.utils = utils
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((settings.HOST, settings.PORT))
        self.sock.listen(settings.MAX_SOCKET_LISTEN)
        self.accounts = self.load_accounts()
        self.user = None
        self.user_current_dir = None

    '''start the server'''

    def run(self):
        '''start the server'''
        print('FTP server is running on %s:%s' %
              (settings.HOST, settings.PORT))

        while True:
            self.conn, self.addr = self.sock.accept()
            print('connect from: ', self.addr)
            try:
                self.handle()
            except Exception as e:
                print('error: Something wrong with client, close connection!', e)
                self.conn.close()

    '''handle the connection'''

    def handle(self):
        '''handle the connection'''
        while True:
            raw_data = self.conn.recv(1024)
            if not raw_data:
                return
            print('----->', raw_data)
            data = json.loads(raw_data.decode("utf-8"))
            action_type = data.get('action_type')
            if action_type:
                if hasattr(self, "_%s" % action_type):
                    func = getattr(self, "_%s" % action_type)
                    func(data)
            else:
                print('invalid command')

    def load_accounts(self):
        '''load the user accounts from the accounts.ini file'''
        self.accounts = {}
        config = configparser.ConfigParser()
        config.read(settings.ACCOUNT_FILE)
        print(config.sections())
        return config

    def authenicate(self, username, password):
        '''authenticate the user'''
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
                return True
            print('incorrect username or password')
            return False
        print('incorrect username or password2')
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

    '''authenticate the user'''

    def _auth(self, data):
        '''authenticate the user'''
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
                print('file sent successfully to the client from ', full_path)
        else:
            self.send_response(status_code=300)

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
            print('file [%s] uploaded done! Sent file size is [%s]' %
                  (full_path, received_size))
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
            print('relative_path: ', relative_path)
            self.send_response(status_code=310, current_dir=relative_path)
        else:
            self.send_response(status_code=311)

    def _mkdir(self, data):
        '''create a directory'''
        '''create a directory in the self.user_current_dir'''
        dir_name = data.get('dir_name')
        full_path = os.path.join(self.user_current_dir, dir_name)
        if not os.path.exists(full_path):
            os.mkdir(full_path)
            self.send_response(status_code=320)
        else:
            self.send_response(status_code=321)

    def load_accounts(self):
        config = configparser.ConfigParser()
        # Construct the path to the configuration file
        config_path = os.path.join(os.path.dirname(
            __file__), '..', 'conf', 'accounts.ini')
        config.read(config_path)
        accounts = {section: dict(config.items(section))
                    for section in config.sections()}
        print("Accounts loaded: ", accounts)  # Debugging
        return accounts

    def save_accounts(self):
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
        print("Accounts saved: ", self.accounts)  # Debugging

    def _create_user(self, data):
        username = data.get('username')
        password = hashlib.md5(data.get('password').encode()).hexdigest()
        if username not in self.accounts:
            self.accounts[username] = {'password': password}
            os.makedirs(os.path.join(
                settings.USER_BASE_DIR, username), exist_ok=True)
            self.save_accounts()
            self.send_response(200, "User created successfully.")
            print("User created: ", username)  # Debugging
        else:
            self.send_response(400, "Username already exists.")
            print("Failed to create user: Username already exists.")  # Debugging
