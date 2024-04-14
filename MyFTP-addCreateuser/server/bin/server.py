import os
import sys

# Determine the base directory of the server application. This is assumed to be the grandparent directory
# of this script's directory, which often contains the main project structure.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add the base directory to the system path. This allows for the importation of modules across the project
# without needing relative paths, facilitating easier module management and cleaner code.
sys.path.append(BASE_DIR)

# Check if the script is being run directly. This is standard boilerplate in Python scripts to ensure that
# the script is not run when being imported as a module in other scripts.
if __name__ == '__main__':
    # Import the Utils class from the helper module within the core package. The core package typically contains
    # essential functionality for the application, and helper modules support common tasks.
    from core import helper

    # Create an instance of the Utils class, initializing it with command line arguments provided to the script.
    # This allows the Utils class to process and react to command line input.
    utils = helper.Utils(sys.argv)

    # Execute the main functionality of the Utils instance. Depending on the implementation of Utils,
    # this may start the server, perform initial setup tasks, or handle command-line operations provided by the user.
    utils.execute()
