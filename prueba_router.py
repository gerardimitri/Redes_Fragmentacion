import socket
import sys

headers = sys.argv[1]
IP_router_init = sys.argv[2]
port_router_init = sys.argv[3]

filename = "test_file.txt"

test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(filename, "r") as file:
    for line in file:
        message_to_send = headers + "," + line
        test_socket.sendto(message_to_send.encode(), (IP_router_init, int(port_router_init)))