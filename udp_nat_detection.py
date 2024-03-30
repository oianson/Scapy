import random
from scapy.all import IP, UDP, send

def send_udp_traffic(target_ip, source_port, ttl):
    """
    Send a UDP packet to the target IP address with the specified TTL value (63 by default)
    This simulates a VM Hypervisor using a network adapter in NAT mode which should reduce the TTL by 1, typically from 128 for Windows
    or 64 for Linux/MacOS. The destination port is hardcored to 12345 but could be changed.
    
    This was created to test NAT detection in DNAC

    :param target_ip: The target IP address
    :param source_port: The source port
        """
    udp_packet = IP(dst=target_ip, ttl=ttl) / UDP(sport=source_port, dport=12345) / b''

    # Send the UDP packet
    send(udp_packet, verbose=False)

    print(f"Sent UDP packet to {target_ip} from port {source_port} with TTL {ttl}")

if __name__ == "__main__":
    target_ip = '1.2.3.4'
    ttl = 63

    # Define the number of flows
    num_flows = 15

    # Iterate through each flow
    for flow in range(num_flows):
        # Generate a random source port
        source_port = random.randint(1024, 65535)

        # Send UDP traffic
        send_udp_traffic(target_ip, source_port, ttl)
