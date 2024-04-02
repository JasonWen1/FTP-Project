import socket
from conf import settings


class FTPServer(object):
    '''FTP server class'''
    def __init__(self, utils):
        self.utils = utils
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((settings.HOST, settings.PORT))
        self.sock.listen(settings.MAX_SOCKET_LISTEN)
    
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
        data = self.conn.recv(1024)
        if not data:
            return
        print(data)
            
            