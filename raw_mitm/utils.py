from raw_mitm.logger import Logger

import subprocess
import sys
import os

def check_permissions() -> None:
    if "SUDO_UID" not in os.environ.keys():
        Logger.error("You need root privileges!")
        sys.exit(-1)

def allow_ip_forwarding(not_allow=False) -> None:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        ip_forward_value = f.read().strip()

    if not_allow:
        if int(ip_forward_value) == 1:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                subprocess.Popen(["echo", "0"], stdout=f).wait()
                f.close()
        return

    if int(ip_forward_value) == 1:
        return
        
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        subprocess.Popen(["echo", "1"], stdout=f).wait()
        f.close()

def get_interface() -> str:
    return os.listdir("/sys/class/net")[1]

def get_router_ip() -> str:
    return subprocess.run(["ip", "route"], 
        capture_output=True
    ).stdout.decode().strip().split("\n")[0].strip().split(" ")[2]

def get_device_mac_address() -> str:
    return subprocess.run(["ifconfig"],
        capture_output=True
    ).stdout.decode().strip().split("\n")[3].strip().split(" ")[1]

def get_target_mac_address() -> str:
    pass

def get_router_mac_address() -> str:
    pass
