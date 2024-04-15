import socket
import optparse
import json
import os


class FTPClient(object):
    '''FTP client class'''

    MSG_SIZE = 1024
    RECV_SIZE = 8192

    def __init__(self):
        self.username = None
        self.current_dir = None
        self.terminal_display = None
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
            self.current_dir = '/'
            self.terminal_display = "[/%s]>>:" % self.username
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
                user_input = input(self.terminal_display).strip()
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


    def _ls(self, cmd_list):
        '''list files in the server current directory'''
        self.send_msg(action_type='ls')
        response = self.get_response()
        if response.get('status_code') == 302:
            cmd_result_size = response.get('cmd_result_size')
            received_size = 0
            cmd_result = b''
            while received_size < cmd_result_size:
                if cmd_result_size - received_size < self.RECV_SIZE:
                    data = self.sock.recv(cmd_result_size - received_size)
                else:
                    data = self.sock.recv(self.RECV_SIZE)
                received_size += len(data)
                cmd_result += data
            print(cmd_result.decode())


    def _cd(self, cmd_list):
        '''change the server current directory'''
        if self.check_cmd_params(cmd_list, exact_params=1):
            target_dir = cmd_list[0]
            self.send_msg(action_type='cd', target_dir=target_dir)
            response = self.get_response()
            print(response.get('status_msg'))
            if response.get('status_code') == 310:
                self.terminal_display = "[/%s%s]" % (self.username, response.get('current_dir'))
                self.current_dir = response.get('current_dir')
    

    def _mkdir(self, cmd_list):
        '''create a directory in the server'''
        if self.check_cmd_params(cmd_list, exact_params=1):
            dir_name = cmd_list[0]
            self.send_msg(action_type='mkdir', dir_name=dir_name)
            response = self.get_response()
            print(response.get('status_msg'))
            if response.get('status_code') == 320:
                print('Successfully created directory [%s]' % dir_name)
            else:
                print('Failed to create directory [%s]' % dir_name)

def _rmdir(self, cmd_list):
        """
        Sends a request to remove an empty directory on the server.
        The method checks if the directory is empty before removal and updates the local current directory if necessary.

        Args:
        cmd_list (list): A list containing the directory name to be removed.

        The method sends a request to remove an empty directory and updates the current working directory based on the server's response.
        It handles various responses such as successful removal, failure due to non-empty directory, or other errors.
        """
        if self.check_cmd_params(cmd_list, exact_params=1):
            dir_name = cmd_list[0]
            self.send_msg(action_type='rmdir', dir_name=dir_name)
            response = self.get_response()
            print(response.get('status_msg'))
            if response.get('status_code') == 320:
                print('Successfully removed directory [%s]' % dir_name)
                if 'current_dir' in response:
                    # Update local current directory
                    self.current_dir = response['current_dir']
                    print('Current directory updated to: %s' %
                          self.current_dir)
            elif response.get('status_code') == 321:
                print('Directory is not empty [%s]' % dir_name)
            else:
                print('Failed to remove directory [%s]' % dir_name)

    def progress_bar(self, total_size,current_percent=0,last_percent=0):
        '''display the progress bar'''
        while True:
            received_size = yield current_percent
            current_percent = int(received_size / total_size *100)

            if current_percent > last_percent:
                print("#" * int(current_percent / 2) + "{percent}%".format(percent=current_percent), end='\r',
                      flush=True)
                last_percent = current_percent 
            


    def _get(self, cmd_list):
        '''get file from the server'''
        if self.check_cmd_params(cmd_list, exact_params=1):
            filename = cmd_list[0]
            self.send_msg('get', filename=filename)
            response = self.get_response()
            if response.get('status_code') == 301:
                file_size = response.get('file_size')
                # get the filename from the full path
                filename1 = filename.split('/')[-1]
                received_size = 0
                progress = self.progress_bar(file_size)
                next(progress)
                with open(filename1, 'wb') as f:
                    while received_size < file_size:
                        if file_size - received_size < self.RECV_SIZE:
                            data = self.sock.recv(file_size - received_size)
                        else:
                            data = self.sock.recv(self.RECV_SIZE)
                        received_size += len(data)
                        f.write(data)
                        progress.send(received_size)
                    else:
                        print('file [%s] received done! Received file size is [%s]' % (filename, file_size))
            else:
                print(response.get('status_msg'))

    
    def _put(self, cmd_list):
        '''
        put file to the server
        1. check the file exists
        2. get the file name and file size and send to the server
        3. send the file to the server
        '''

        if self.check_cmd_params(cmd_list, exact_params=1):
            local_file = cmd_list[0]
            if os.path.isfile(local_file):
                file_size = os.stat(local_file).st_size
                self.send_msg('put', filename = local_file, file_size=file_size)
                f = open(local_file, 'rb')
                uploaded_size = 0
                progress = self.progress_bar(file_size)
                next(progress)
                for line in f:
                    self.sock.send(line)
                    uploaded_size += len(line)
                    progress.send(uploaded_size)
                else:
                    print('\n')
                    print('file [%s] uploaded done! Sent file size is [%s]' % (local_file, file_size))
                    f.close()


    def _rm(self, cmd_list):
        """
        Sends a request to remove a file on the server.
        This method checks command parameters for correctness before sending a delete request.

        Args:
        cmd_list (list): A list containing the filename to be deleted.

        The method sends a delete request to the server and processes the response,
        displaying an appropriate message based on whether the deletion was successful.
        """
        if self.check_cmd_params(cmd_list, exact_params=1):
            filename = cmd_list[0]
            self.send_msg(action_type='rm', filename=filename)
            response = self.get_response()
            print(response.get('status_msg'))
            if response.get('status_code') == 301:
                print(f'Successfully removed file [{filename}]')
            else:
                print(f'Failed to remove file [{filename}]')

    def _rm_rf(self, cmd_list):
        """
        Sends a request to recursively remove a directory and its contents on the server.
        This method checks if the correct number of command parameters are provided before sending the request.

        Args:
        cmd_list (list): A list containing the directory name to be deleted recursively.

        The method sends a recursive deletion request to the server and handles the response,
        indicating success or failure of the directory removal.
        """
        if self.check_cmd_params(cmd_list, exact_params=1):
            dir_name = cmd_list[0]
            self.send_msg(action_type='rm_rf', dir_name=dir_name)
            response = self.get_response()
            print(response.get('status_msg'))
            if response.get('status_code') == 320:
                print(
                    f'Successfully removed directory and all contents [{dir_name}]')
            else:
                print(f'Failed to remove directory [{dir_name}]')




if __name__ == '__main__':
    client = FTPClient()
    # enter the interactive mode
    client.interactive()
