"""
The purpose of this script is to create a DHCP renew packet with chaddr != source mac and broadcast bit set

Creates a DHCP request packet which is styled like a renew request
- Source IP of the packet (src_ip) is the client's IP address (ciaddr)
- Destination IP of the packet (dst_ip) is the DHCP Server IP address, as the src IP and dst IP are  provided, along with ciaddr, this suggests it is a DHCP Renew
- Source MAC address of the Ethernet frame (src_mac) should be taken from the adapter
- Option 61 and CHADDR are set to (vm_mac).
- The BOOTP broadcast flag is set
"""

import random
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp

def mac_to_bytes(mac_addr: str) -> bytes:
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def create_dhcp_request(dst_mac, src_ip, dst_ip, vm_mac):
    ether_layer = Ether(dst=dst_mac)
    ip_layer = IP(src=src_ip, dst=dst_ip)
    udp_layer = UDP(sport=68, dport=67)

    # Generate a random DHCP transaction ID
    transaction_id = random.randint(1, 0xFFFFFFFF)

    # Set the broadcast flag, chaddr and ciaddr
    bootp_layer = BOOTP(op=1, xid=transaction_id, flags=0x8000, chaddr=mac_to_bytes(vm_mac), ciaddr=src_ip)

    # Set DHCP message-type (option 53) as Request and Client Identifier (Option 61) as the VM MAC address
    dhcp_layer = DHCP(options=[
        ("message-type", "request"),
        ("client_id", bytes([0x01]) + mac_to_bytes(vm_mac)),  # Using type 0x01 for Ethernet MAC address
        "end"
    ])

    # Combine all layers to create the DHCP request packet
    dhcp_request_packet = ether_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer
    return dhcp_request_packet


if __name__ == "__main__":
    # MAC address of the relay-agent (SVI typically)
    dst_mac = "c4:b3:6a:31:b6:75"
    # Will be used to source the IP packet and used for CIADDR (IP that is being requested for renewal
    src_ip = "192.168.49.200"
    # DHCP Server IP Address
    dst_ip = "172.16.2.100"
    # Will go into CHADDR and Option 61, if different than the source MAC address of Ethernet frame, ACRO will be triggered
    vm_mac = "00:0c:29:1a:2c:4b"

    dhcp_request_packet = create_dhcp_request(dst_mac, src_ip, dst_ip, vm_mac)

    sendp(dhcp_request_packet)
