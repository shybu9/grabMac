import sys
from colorama import Fore, init
import pyfiglet as fig
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether

# __COLOURS
init()
yellow = Fore.LIGHTYELLOW_EX
red = Fore.LIGHTRED_EX
green = Fore.LIGHTGREEN_EX
blue = Fore.LIGHTBLUE_EX
cyan = Fore.LIGHTCYAN_EX
pink = Fore.MAGENTA
reset = Fore.RESET

# __TITLE
title = (fig.figlet_format("grab MAC"))
print(yellow + title + reset)
print(f"                                        ~{cyan}*.*{red} SHY.BUG {cyan}*.*{reset}")

if sys.argv[1] == "-h":
    print(f"{pink}THIS TOOL DUMPS THE IPs and their MAC addresses of target network{reset}\n"
          f"cmd:= {blue} python3 {sys.argv[0]} -ip <ipaddress>{reset}\n\n")
try:
    ip = sys.argv[2]
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip)
    probe = ether / arp
    op = srp(probe, timeout=5)
    responded = op[0]

    ip_mac_data = []

    for sent, received in responded:
        ip_mac_data.append({'ip': received.psrc, 'mac': received.hwsrc})

    for data in ip_mac_data:
        print(f"{data['ip']}\t{data['mac']}")

except:
    print(f"\n{cyan}......try entering a valid ip")
