from scapy.all import ARP, Ether, srp
import threading
import socket
import time

startTime= time.monotonic()

def scan_network(ip_range):
    """
    Scans an IP range for active devices using Address Resolution Protocol (ARP).

    Args:
        ip_range (str): The IP range to scan in CIDR notation (e.g., "192.168.1.0/24").

    Returns:
        list: A list of dictionaries where each dictionary contains
              'ip' and 'mac' keys representing the IP address and MAC address
              of a discovered device.
    """

    # Create an ARP request packet with the destination IP set to the provided range.
    arp = ARP(pdst=ip_range)

    # Create an Ethernet frame with the destination MAC address set to broadcast,
    # ensuring it reaches all devices on the network.
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the ARP request and Ethernet frame.
    packet = ether / arp

    # Send the combined packet using Scapy's `srp` function and wait for responses
    # for up to 10 seconds.
    result = srp(packet, timeout=10, verbose=0)[0]

    # Parse the received ARP responses and extract the IP and MAC addresses
    # of responding devices.
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def scan_ports(ip):
    """
    Scans the open ports on a specific IP address.

    Args:
        ip (str): The IP address of the target device.

    Returns:
        list: A list of open port numbers found on the target device.
    """

    open_ports = []
    # Iterate through ports 1 to 1024.
    for port in range(1, 1025):
        # Create a socket using the `socket` module.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout of 3 seconds for connection attempts.
        sock.settimeout(3.0)

        # Attempt to connect to the target device on the current port.
        result = sock.connect_ex((ip, port))

        # If the connection is successful (result is 0), add the port number
        # to the `open_ports` list.
        if result == 0:
            open_ports.append(port)

        # Close the socket.
        sock.close()

    return open_ports

def scan_ports_thread(ip, results, index):
    """
    Scans the ports of a specific IP address within a separate thread.

    Args:
        ip (str): The IP address of the target device.
        results (list): A list to store the port scan results for each device.
        index (int): The index of the target device in the `results` list.
    """

    # Call the `scan_ports` function to perform the actual port scanning.
    open_ports = scan_ports(ip)

    # Save the result (list of open ports) in the `results` list at the
    # specified `index`.
    results[index] = open_ports

def main():
    """
    Main function that runs the network scanning tool.
    """

    print("Network Scanning Tool: Starting...")

    # Display the menu for network scanning options.
    menu_choice = int(input())

    if menu_choice == 1:
        # Implement the scan_ip_range function to scan an IP range
        ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
        scan_network(ip_range)

    elif menu_choice == 2:
        # Implement the scan_ports_of_ip function to scan ports of a specific IP
        ip = input("Enter the IP address to scan ports on: ")
        scan_ports(ip)

    elif menu_choice == 3:
        print("Exiting network scanning tool.")
        exit()

# Main program execution
if __name__ == "__main__":
    main()

print("Network Scanning Tool: Completed in {:.2f} seconds.".format(time.monotonic() - startTime))
