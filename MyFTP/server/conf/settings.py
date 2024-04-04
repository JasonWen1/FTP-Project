import os
# get the path of the server directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# get the path of the user directory
USER_BASE_DIR = os.path.join(BASE_DIR, 'home')

# get the path of the log directory
LOG_DIR = os.path.join(BASE_DIR, 'log')

# host and port of the server
HOST = '0.0.0.0'
PORT = 9998

# maximum number of connections to the server
MAX_SOCKET_LISTEN = 5

# path of the accounts.ini file where the user accounts are stored
ACCOUNT_FILE = os.path.join(BASE_DIR, 'conf', 'accounts.ini')
