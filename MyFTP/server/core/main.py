import socket
from conf import settings
import json
import configparser
import hashlib

class FTPServer(object):
    '''FTP server class'''

    STATUS_CODE = {
        200: 'Passed authentication!',
        201: 'Incorrect username or password!'
    }

    MSG_SIZE = 1024


    def __init__(self, utils):
        self.utils = utils
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((settings.HOST, settings.PORT))
        self.sock.listen(settings.MAX_SOCKET_LISTEN)
        self.accounts = self.load_accounts()
    

    '''start the server'''
    def run(self):
        '''start the server'''
        print('FTP server is running on %s:%s' % (settings.HOST, settings.PORT))
        
        while True:
            self.conn, self.addr = self.sock.accept()
            print('connect from: ', self.addr)
            self.handle()
    

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
            data['fill'] = data['fill'].zfill(self.MSG_SIZE - len(data_in_bytes))
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