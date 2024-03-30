"""
The purpose of this script is to create a DHCP INFORM packet
- Source IP of the packet (src_ip) is the client's IP address (ciaddr)
- Destination IP of the packet (dst_ip) is the DHCP Server IP address, as the src IP and dst IP are  provided, along with ciaddr
- Source MAC address of the Ethernet frame (src_mac) should be taken from the adapter
"""

import random
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp

def mac_to_bytes(mac_addr: str) -> bytes:
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def create_dhcp_inform(dst_mac, src_ip, dst_ip, vm_mac):
    ether_layer = Ether(dst=dst_mac)
    ip_layer = IP(src=src_ip, dst=dst_ip)
    udp_layer = UDP(sport=68, dport=67)

    transaction_id = random.randint(1, 0xFFFFFFFF)

    bootp_layer = BOOTP(op=1, xid=transaction_id, chaddr=mac_to_bytes(vm_mac))

    # Set DHCP message-type (Option 53) as INFORM
    dhcp_options = [
        ("message-type", "inform"),
        ("param_req_list", ([1, 3, 6, 12, 15, 28])),  # Requesting options 1, 3, 6, 12, 15, 28
        ("vendor_class_id", b"MyVendorClass"),  # Vendor Class Identifier
        ("hostname", b"MyHostname"),  # Hostname
        ("fqdn", b"MyClient.example.com"),  # Client FQDN
        ("user_class", b"MyUserClass"),  # User Class
        "end"
    ]
    dhcp_layer = DHCP(options=dhcp_options)

    # Combine all layers to create the DHCPINFORM packet
    dhcp_inform_packet = ether_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer
    return dhcp_inform_packet


if __name__ == "__main__":
    # MAC address of the relay-agent (SVI typically)
    dst_mac = "00:00:0c:7:ac:2e"
    # Will be used to source the IP packet and used for CIADDR (IP that is being requested for renewal
    src_ip = "10.209.0.83"
    dst_ip = "172.16.2.100"
    vm_mac = "00:0c:29:1a:2c:4b"

    dhcp_inform_packet = create_dhcp_inform(dst_mac, src_ip, dst_ip, vm_mac)

    sendp(dhcp_inform_packet)

