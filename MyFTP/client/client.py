import socket
import optparse
import json


class FTPClient(object):
    '''FTP client class'''

    MSG_SIZE = 1024
    RECV_SIZE = 8192

    def __init__(self):
        self.username = None
        parser = optparse.OptionParser()
        parser.add_option('-s', '--server', dest='server', help='ftp server ip address')
        parser.add_option('-P', '--port', dest='port', help='ftp server port')
        parser.add_option('-u', '--username', dest='username', help='ftp username')
        parser.add_option('-p', '--password', dest='password', help='ftp password')
        self.options, self.args = parser.parse_args()

        print(self.options, self.args)
        self.check_args()
        self.connect()
    

    '''check the command line arguments'''
    def check_args(self):
        '''check the command line arguments'''
        if not self.options.server or not self.options.port:
            print('Error: Please specify the server and port!')
            exit(1)
        
        if (not self.options.username and self.options.password) or (self.options.username and not self.options.password):
            print('Error: username and password should provided together!')
            exit(1)
    
        '''check port number'''
        if (int)(self.options.port) > 65535 or (int)(self.options.port)< 0:
            print('Error: port number should be between 0 and 65535!')
            exit(1)


    '''connect to the server'''
    def connect(self):
        '''connect to the server'''
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.options.server, int(self.options.port)))


    ''' authenticate the user'''
    def auth(self):
        '''authenticate the user'''
        if self.options.username and self.options.password:
            return self.auth_user(self.options.username, self.options.password)
        else:
            # 3 times maximum retry to get the input of username and password
            count = 0
            while count < 3:
                username = input("username:").strip()
                password = input("password:").strip()
                if self.auth_user(username, password):
                    return True
                count += 1
            return False
        
    
    ''' authenticate user with username and password'''
    def auth_user(self, username, password):
        '''authenticate user with username and password'''
        cmd = {
            'action_type': 'auth',
            'username': username,
            'password': password
        }
        self.sock.send(json.dumps(cmd).encode("utf-8"))
        response = self.get_response()
        print('response:', response)
        if response.get('status_code') == 200:
            self.username = username
            return True
        else:
            print(response.get('status_msg'))
            return False


    '''get the response from the server'''
    def get_response(self):
        '''get the response from the server'''
        data = self.sock.recv(self.MSG_SIZE)
        response = json.loads(data.decode())
        return response

    '''interactive mode'''
    def interactive(self):
        if  self.auth():
            while True:
                user_input = input("[%s]>>:" % self.username).strip()
                if not user_input:
                    continue

                cmd_list = user_input.split()
                if hasattr(self, "_%s" % cmd_list[0]):
                    func = getattr(self, "_%s" % cmd_list[0])
                    func(cmd_list[1:])
                else:
                    print('Invalid command!')
    
    ''' check the parameters of the command in the interactive mode'''
    def check_cmd_params(self, cmd_list, min_params=None, max_params=None, exact_params=None):
        '''check the parameters of the command'''
        if min_params:
            if len(cmd_list) < min_params:
                print('Error: too few parameters!')
                return False
        if max_params:
            if len(cmd_list) > max_params:
                print('Error: too many parameters!')
                return False
        if exact_params:
            if len(cmd_list) != exact_params:
                print('Error: wrong number of parameters!')
                return False
        return True


    def send_msg(self, action_type, **kwargs):
        '''send standard message to the server'''
        msg_data = {
            'action_type': action_type,
            'fill': ''
        }
        msg_data.update(kwargs)

        bytes_data = json.dumps(msg_data).encode('utf-8')
        if self.MSG_SIZE > len(bytes_data):
            msg_data['fill'] = msg_data['fill'].zfill(self.MSG_SIZE - len(bytes_data))
            bytes_data = json.dumps(msg_data).encode()
        
        self.sock.send(bytes_data)


    def _get(self, cmd_list):
        '''get file from the server'''
        if self.check_cmd_params(cmd_list, exact_params=1):
            filename = cmd_list[0]
            self.send_msg('get', filename=filename)
            response = self.get_response()
            if response.get('status_code') == 301:
                file_size = response.get('file_size')

                received_size = 0
                with open(filename, 'wb') as f:
                    while received_size < file_size:
                        if file_size - received_size < self.RECV_SIZE:
                            data = self.sock.recv(file_size - received_size)
                        else:
                            data = self.sock.recv(self.RECV_SIZE)
                        received_size += len(data)
                        f.write(data)
                        print(file_size, received_size)
                    else:
                        print('file [%s] received done! Received file size is [%s]' % (filename, file_size))
            else:
                print(response.get('status_msg'))
            

if __name__ == '__main__':
    client = FTPClient()
    # enter the interactive mode
    client.interactive()