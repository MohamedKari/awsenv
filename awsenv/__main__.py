import argparse
import sys

from .awsenv import get_credentials, CONFIG_FILE, SESSIONS_FILE


parser = argparse.ArgumentParser()

# order of prcedence:
# - config defaults 
# - config shortcuts
# - command line arguments

parser.add_argument("shortcut", nargs="?")
parser.add_argument("-r", "--role", default=None, help="The role to assume. If no role should be assumed, indicate '.' (a dot).")
parser.add_argument("-u", "--user", default=None)
parser.add_argument("-a", "--account", default=None)
parser.add_argument("-d", "--duration", default=None, type=int)
parser.add_argument("-c", "--config", default=CONFIG_FILE, dest="config_file")
parser.add_argument("-s", "--sessions", default=SESSIONS_FILE, dest="sessions_file")
parser.add_argument("-q", "--quiet", action="store_true", help="Suppresses printing credentials")

args = parser.parse_args(sys.argv[1:])

get_credentials(
    shortcut=args.shortcut,
    role=args.role,
    user=args.user,
    account=args.account,
    duration=args.duration,
    config_file=args.config_file,
    sessions_file=args.sessions_file,
    print_credentials=(not args.quiet)
)
