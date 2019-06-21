#
#  interface.py
#  EastWinds
#
#  Created by Noirdemort.
#

from coreutils import CommandLine


def account_interface():
    print("[*] Choose an action:")
    print("1. Login \n2. Sign-up \n3. Delete Account")
    print("Example: Enter 1 for Login")
    choice = CommandLine.get_input("Account action code")
    if choice in ["1", "2", "3"]:
        return int(choice)
    return 0
