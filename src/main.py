import argparse
from sys import stderr
from password_storage import PasswordManager


def handleArgErrors(args):
    if(args.action == ""):
        print("Error: Need to provide action (init, put, get)", file=stderr)
        exit(1)
    if(args.password == ""):
        print("Error: Need to provide password", file=stderr)
        exit(1)
    if(args.action == "init"):
        if(args.password == ""):
            print("Error: Need to provide password", file=stderr)
            exit(1)
        elif(args.adress != "" or args.new_password != ""):
            print("Wrong number of arguments. Expected 2", file=stderr)
            exit(1)
    elif(args.action == "put"):
        if(args.adress == ""):
            print("Error: Need to provide adress", file=stderr)
            exit(1)
        if(args.new_password == ""):
            print("Error: Need to provide new password", file=stderr)
            exit(1)
        elif(args.adress == "" or args.new_password == ""):
            print("Wrong number of arguments. Expected 4", file=stderr)
            exit(1)
    elif(args.action == "get"):
        if(args.adress == ""):
            print("Error: Need to provide adress", file=stderr)
            exit(1)
        elif(args.adress == "" or args.new_password != ""):
            print("Wrong number of arguments. Expected 3", file=stderr)
            exit(1)
    else:
        print("Error: Invalid action. Must be: init, put, get", file=stderr)
        exit(1)


arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("--action", dest="action", default="", required=True)
arg_parser.add_argument("--password", dest="password", default="", required=True)
arg_parser.add_argument("--adress", dest="adress", default="", required=False, nargs="?", const="")
arg_parser.add_argument("--new_password", dest="new_password", default="", required=False, nargs="?", const="")

args = arg_parser.parse_args()

handleArgErrors(args)

password_manager = PasswordManager()
password_manager.setState()

if(args.action == "get"):
    password_manager.getPassword(args.password, args.adress)
elif(args.action == "put"):
    password_manager.storePassword(args.password, args.adress, args.new_password)
else:
    password_manager.initializeNewPasswordManager(args.password)

