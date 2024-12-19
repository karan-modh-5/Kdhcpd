import socket
import struct
import ipaddress
import socket
import argparse
import re
import sys

# Dictionary to track assigned IPs
leases = {}
version = 1.6

# Variables for storing input parameters
start_ip = ""
end_ip = ""
subnet_mask = ""
gateway_ip = ""
dns_ip = ""

# Function to validate if the input is a valid IP address
def is_valid_ip(ip):
    ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") # Regular expression for IPv4
    return bool(ip_pattern.match(ip))  # Return True if valid, False otherwise    

# Function to validate subnet mask input
def is_valid_subnet_mask(subnet_mask):
    try:
        subnet = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)  # Parse subnet mask
        return not subnet.with_prefixlen.endswith('/0')  # Ensure the subnet is valid
    except ValueError:
        return False

# Argument parser setup for command-line inputs
parser = argparse.ArgumentParser(description="grandstream zero configuration auto provisioning server")
parser.add_argument("-v", action="store_true", help="Print version info")
parser.add_argument("-n", help="Subnet Mask")
parser.add_argument("-g", help="Gateway IP Address")
parser.add_argument("-d", help="DNS IP Address")
parser.add_argument("-G", action="store_true", help="Provide IP Address to only Grandtream devices")
parser.add_argument("-DS", help="Starting DHCP IP Address")
parser.add_argument("-DE", help="End DHCP IP Address")
parser.add_argument("-V", "--verbose", action="store_true", help="Enable verbose mode")

# Parse the command-line arguments
args = parser.parse_args()

# Handle version argument
if args.v:
    print("\nkdhcpd version: {}".format(version))
    sys.exit(0)

if args.n:
    try:
        if int(args.n) <= 32:
            print("Invalid IP address. Please enter a valid Subnet Mask.")
    except:
        if is_valid_subnet_mask(args.n):
            subnet_mask = args.n

if args.g:
    if is_valid_ip(args.g):
        gateway_ip = args.g

if args.d:
    if is_valid_ip(args.d):
        dns_ip = args.d

if args.DS:
    if is_valid_ip(args.DS):
        start_ip = args.DS
        
if args.DE:
    if is_valid_ip(args.DE):
        end_ip = args.DE

# Verbose flag
VERBOSE_MODE = args.verbose

def log_verbose(message):
    """Print verbose messages if verbose mode is enabled."""
    if VERBOSE_MODE:
        print(f"[VERBOSE] {message}")

# Function to display a progress bar
def progress_bar(progress, total):
    percent = 100 * (progress / float(total))
    terminal_width, _ = shutil.get_terminal_size()
    if terminal_width > 80:
        terminal_width = 80

    bar_width = int((terminal_width - 10) * (percent / 100))
    bar = '>' * bar_width + ' ' * (terminal_width - 10 - bar_width)

    print(f"\r[{bar}] {percent:.2f}%", end="\r")

ALLOWED_OUIS = [
    "00:0B:82",  # Example Grandstream OUI
    "00:0B:46",
    "AC:CF:23",
    "C0:74:AD",
    "EC:74:D7",
]

def is_grandstream_device(mac_address):
    """Check if the MAC address belongs to a Grandstream device."""
    mac_prefix = mac_address.upper()[:8]
    return mac_prefix in ALLOWED_OUIS

def get_local_ip(network_segment, network):
    """
    Automatically fetch the server's IP that matches the given network segment.
    """
    hostname = socket.gethostname()
    local_ips = socket.gethostbyname_ex(hostname)[2]
    for ip in local_ips:
        if ipaddress.IPv4Address(ip) in network:
            return ip
    raise ValueError("No local IP matches the specified network segment.")


def generate_ip_pool(network_segment, start_ip, end_ip, network):
    """
    Generate a list of individual IPs within the specified range in the given network segment.
    """
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    if start not in network or end not in network:
        raise ValueError("Start or end IP is outside the specified network segment.")

    # Generate all individual IPs within the range
    return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]

def build_dhcp_packet(transaction_id, client_ip, server_ip, mac_address, lease_time, subnet_mask, broadcast_address, network, gateway_ip, dns_ip, message_type):

    # Ensure transaction_id is an integer
    if not isinstance(transaction_id, int):
        raise ValueError(f"Transaction ID must be an integer, got {type(transaction_id)}")

    # Convert IPs to binary format
    client_ip_bin = socket.inet_aton(client_ip)
    server_ip_bin = socket.inet_aton(server_ip)
    subnet_mask_bin = socket.inet_aton(subnet_mask)  # Default subnet mask
    broadcast_address_bin = socket.inet_aton(broadcast_address)  # Replace with appropriate broadcast
    router_bin = socket.inet_aton(str(gateway_ip))  # Default router is the server IP
    dns_server_bin = socket.inet_aton(dns_ip)  # Default DNS server is the server IP
    lease_time_bin = struct.pack("!I", int(lease_time))  # Lease time
    renewal_time_bin = struct.pack("!I", int(lease_time // 2))  # Renewal time (T1)
    rebinding_time_bin = struct.pack("!I", int(lease_time * 0.875))  # Rebinding time (T2)

    # DHCP header
    dhcp_header = struct.pack(
        "!BBBBIHHIIII16s64s128s4s",
        2,  # Message type: Boot Reply
        1,  # Hardware type: Ethernet
        6,  # Hardware address length
        0,  # Hops
        transaction_id,  # Transaction ID
        0,  # Seconds elapsed
        0,  # Bootp flags
        0,  # Client IP address (usually 0 for initial response)
        struct.unpack("!I", client_ip_bin)[0],  # Your (client) IP address
        struct.unpack("!I", server_ip_bin)[0],  # Next server IP address
        0,  # Relay agent IP address
        bytes.fromhex(mac_address.replace(':', '')),  # Client MAC address
        b'\x00' * 64,  # Server host name
        b'\x00' * 128,  # Boot file name
        b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    )

    offer_bit = (
        b'\x35\x01\x02'  # DHCP Message Type: Offer
    )
    
    ack_bit = (
        b'\x35\x01\x05'  # DHCP Message Type: ACK
    )
    
    # DHCP options
    other_dhcp_options = (
        b'\x36\x04' + server_ip_bin  # DHCP Server Identifier
        + b'\x33\x04' + lease_time_bin  # Lease Time
        + b'\x3a\x04' + renewal_time_bin  # Renewal Time Value (T1)
        + b'\x3b\x04' + rebinding_time_bin  # Rebinding Time Value (T2)
        + b'\x01\x04' + subnet_mask_bin  # Subnet Mask
        + b'\x1c\x04' + broadcast_address_bin  # Broadcast Address
        + b'\x03\x04' + router_bin  # Router
        + b'\x06\x04' + dns_server_bin  # DNS Server
        + b'\x0f' + bytes([len("lan")]) + b'lan'  # Domain Name (adjust as needed)
        + b'\xff'  # End option
    )

    if message_type == 1:
        padding = b'\x00' * (300 - len(dhcp_header + offer_bit + other_dhcp_options))
        return dhcp_header + offer_bit + other_dhcp_options + padding
    if message_type == 3:
        padding = b'\x00' * (300 - len(dhcp_header + ack_bit + other_dhcp_options))
        return dhcp_header + ack_bit + other_dhcp_options + padding

def handle_dhcp_request(data, addr, ip_pool, server_ip, lease_time, server_socket, subnet_mask, broadcast_address, network, gateway_ip, dns_ip):
    global leases  # Ensure we can access and modify the global 'leases' dictionary

    try:
        # Parse incoming data
        transaction_id = struct.unpack("!I", data[4:8])[0]
        mac_address = ':'.join(f"{b:02x}" for b in data[28:34])
        log_verbose(f"Transaction ID: {transaction_id}, Client MAC: {mac_address}")

        if args.G:
            # Filter non-Grandstream devices
            if not is_grandstream_device(mac_address):
                log_verbose(f"Ignoring DHCP request from non-Grandstream device: {mac_address}")
                return

        # Extract DHCP Message Type (Option 53)
        options = data[240:]  # Skip the fixed header to parse options
        message_type = None
        i = 0
        while i < len(options):
            option_type = options[i]
            if option_type == 53:  # DHCP Message Type
                message_type = options[i + 2]  # The value is 2 bytes ahead
                break
            i += 2 + options[i + 1]  # Move to the next option

        if message_type == 1:  # DHCP DISCOVER
            # Allocate an IP address
            client_ip = ip_pool.pop(0) if mac_address not in leases else leases[mac_address]
            leases[mac_address] = client_ip
            log_verbose(f"Assigning IP {client_ip} to {mac_address}")

            # Build and send DHCP OFFER packet
            offer_packet = build_dhcp_packet(transaction_id, client_ip, server_ip, mac_address, lease_time, subnet_mask, broadcast_address, network, gateway_ip, dns_ip, message_type)
            server_socket.sendto(offer_packet, (broadcast_address, 68))

            log_verbose(f"DHCP OFFER sent to {mac_address} for IP {client_ip}")

        elif message_type == 3:  # DHCP REQUEST
            if mac_address in leases:
                client_ip = leases[mac_address]
                log_verbose(f"Client {mac_address} requested IP {client_ip}")

                # Build and send DHCP ACK packet
                ack_packet = build_dhcp_packet(transaction_id, client_ip, server_ip, mac_address, lease_time, subnet_mask, broadcast_address, network, gateway_ip, dns_ip, message_type)
                server_socket.sendto(ack_packet, (broadcast_address, 68))
                log_verbose(f"DHCP ACK sent to {mac_address} for IP {client_ip}")
                print(f"[LOG] {client_ip} Assigned to {mac_address}")
            else:
                log_verbose(f"Client {mac_address} requested an unknown IP. Ignoring.")

    except Exception as e:
        print(f"Error processing request: {e}")

def run_dhcp_server(ip_pool, server_ip, lease_time, subnet_mask, broadcast_address, network, gateway_ip, dns_ip):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_socket.bind(("0.0.0.0", 67))
    server_socket.settimeout(1.0)  # Set a timeout of 1 second for the socket

    print("DHCP server is running...")

    try:
        while True:
            try:
                data, addr = server_socket.recvfrom(1024)
                log_verbose(f"Received data from {addr}")
                handle_dhcp_request(data, addr, ip_pool, server_ip, lease_time, server_socket, subnet_mask, broadcast_address, network, gateway_ip, dns_ip)
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\nShutting down DHCP server.")
    finally:
        server_socket.close()

def main(start_ip, end_ip, subnet_mask, gateway_ip, dns_ip):
    try:
        print("DHCP Server Configuration")
        #network_segment = input("Enter network segment (e.g., 192.168.1.0/24): ")
        #network_segment = "192.168.1.0/24"
        #start_ip = input("Enter starting IP (e.g., 192.168.1.10): ")
        #start_ip = "192.168.1.10"
        if start_ip == "":
            while True:
                start_ip = input("Enter the starting IP address > ")
                if is_valid_ip(start_ip):
                    if is_valid_subnet_mask(start_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")
        
        #end_ip = input("Enter ending IP (e.g., 192.168.1.50): ")
        #end_ip = "192.168.1.50"
        if end_ip == "":
            while True:
                end_ip = input("Enter the ending IP address > ")
                if is_valid_ip(end_ip):
                    if is_valid_subnet_mask(end_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")
        
        if subnet_mask == "":
            while True:
                print("Enter the Subnet Mask default (255.255.255.0) > ", end="")
                subnet_mask = input() or "255.255.255.0"
                try:
                    if int(subnet_mask) <= 32:
                        print("Invalid IP address. Please enter a valid Subnet Mask.")
                        continue
                except:
                    if is_valid_subnet_mask(subnet_mask):
                        break
                    else:
                        print("Invalid IP address. Please enter a valid Subnet Mask.")
        
        #gateway_ip = input("Enter gateway IP (e.g., 192.168.1.1): ")
        #gateway_ip = "192.168.1.1"
        default_gateway = start_ip.rsplit(".", 1)[0] + ".1"        
        if gateway_ip == "":
            while True:
                print(f"Enter the Gateway IP address default ({default_gateway}) > ", end="")
                gateway_ip = input() or default_gateway
                if is_valid_ip(gateway_ip):
                    if is_valid_subnet_mask(gateway_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")            
        
        #dns_ip = input("Enter DNS IP (e.g., 8.8.8.8): ")
        #dns_ip = "8.8.8.8"
        if dns_ip == "":
            while True:                        
                dns_ip = input("Enter the DNS IP address default (8.8.8.8) > ") or "8.8.8.8"
                if is_valid_ip(dns_ip):
                    if is_valid_subnet_mask(dns_ip):
                        print("Entered value is Subnet Mask not IP Addresss")
                        continue
                    else:
                        break
                else:
                    print("Invalid IP address. Please enter a valid IPv4 address.")
        
        #lease_time = int(input("Enter lease time in seconds (e.g., 3600): "))
        lease_time = 7200  # Ensure this is an integer

        network = ipaddress.IPv4Network(f"{gateway_ip}/{subnet_mask}", strict=False)
        network_segment = str(network)        
        gateway_ip = ipaddress.IPv4Address(gateway_ip)
        broadcast_address = str(network.broadcast_address)
        subnet_mask = str(network.netmask)

        try:
            server_ip = get_local_ip(network_segment, network)
            print(f"Automatically detected server IP: {server_ip}")
        except ValueError as e:
            print(e)
            exit(1)

        ip_pool = generate_ip_pool(network_segment, start_ip, end_ip, network)
        #print(f"IP pool generated: {ip_pool}")
        print("Number of IP Address in Pool", len(ip_pool))
        run_dhcp_server(ip_pool, server_ip, lease_time, subnet_mask, broadcast_address, network, gateway_ip, dns_ip)

    except KeyboardInterrupt:
        print("\nShutting down DHCP server.")
    except Exception as e:
        print(f"Error: {e}")

try:
    if __name__ == "__main__":
        main(start_ip, end_ip, subnet_mask, gateway_ip, dns_ip)
except:
    print("\nkdhcpd Stop Running.")

finally:
    print("\n[kdhcpd_v{}]:".format(version))
