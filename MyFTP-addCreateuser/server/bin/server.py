import os, sys

# get the path of the server directory and add it to the system path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

if __name__ == '__main__':
    from core import helper
    # create an instance of the Utils class and pass the command
    # line arguments to it
    utils = helper.Utils(sys.argv)
    # execute the command
    utils.execute()