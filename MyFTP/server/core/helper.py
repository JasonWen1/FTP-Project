from core import main
class Utils(object):
    # different methods for user input validation and handling

    # initialize the class with the command line arguments
    def __init__(self, argv):
        self.argv = argv
        print(self.argv)
        self.is_valid()
    
    # check if the user input is valid
    def is_valid(self):
        if len(self.argv) < 2:
            self.print_usage()
        cmd = self.argv[1]
        if not hasattr(self, cmd):
            self.print_usage()
    
    # print the usage of the program and exit
    def print_usage(self):
        msg = '''
        valid command is:
        start       start FTP server
        stop        stop FTP　server
        restart     restart FTP server
        createuser  username    create a ftp user

        '''
        print(msg)
        exit(1)
    
    # execute the command
    def execute(self):
        cmd = self.argv[1]
        func = getattr(self, cmd)
        func()

    # start the server
    def start(self):
        print('start ftp server')
        server = main.FTPServer(self)
        server.run()

    # stop the server
    def creteuser(self):
        print(self.sys_argv)
    

