import sys
import socket

router_ip = sys.argv[1]
router_port = int(sys.argv[2])
router_routes = sys.argv[3]

visited = []
visited_max_size = 0
dic_packets = {}

# Socket not connection oriented
router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
router_socket.bind((router_ip, router_port))

# Packet parser
# format: [Dirección IP],[Puerto],[TTL],[ID],[Offset],[Tamaño],[FLAG],[mensaje]
def parse_packet(IP_packet):
    IP_packet = IP_packet.decode()
    IP_packet = IP_packet.split(",")
    return IP_packet

def create_packet(IP_packet):
    IP_packet = ",".join(IP_packet)
    return IP_packet

def get_visited_size(route_file_name, destination_address):
    global visited_max_size
    visited_max_size = 0
    with open(route_file_name, "r") as route_file:
        for line in route_file:
            line = line.split(" ")
            if line[0] == destination_address[0]:
                if int(line[1]) <= destination_address[1] and int(line[2]) >= destination_address[1]:
                    visited_max_size += 1
    return visited_max_size

def check_visited_size():
    global visited_max_size
    global visited
    if len(visited) >= visited_max_size:
        visited = []

# Checks all the routes
# Line format: ip (from port) (until port) (destiny_ip) (destiny_port)
def check_routes(route_file_name, destination_address):
    global visited
    with open(route_file_name, "r") as route_file:
        for line in route_file:
            line = line.split(" ")
            if line[0] == destination_address[0]:
                if int(line[1]) <= destination_address[1] and int(line[2]) >= destination_address[1]:
                    check_visited_size()
                    print("Route found")
                    if (line[3], int(line[4])) in visited:
                        continue
                    else:
                        visited.append((line[3], int(line[4])))
                        return (line[3], int(line[4])), int(line[5])
    return None

IP_packet_v1 = "127.0.0.1,8881,4,0,50,00000300,1,hola".encode()
parsed_IP_packet = parse_packet(IP_packet_v1)
IP_packet_v2_str = create_packet(parsed_IP_packet)
IP_packet_v2 = IP_packet_v2_str.encode()
print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

def fragment_IP_packet(packet, MTU):
    packet_headers = packet[0:7]
    packet_message = packet[7]
    header_size = len(",".join(packet_headers).encode())
    message_size = len(packet_message.encode())
    fragments = []
    offset = int(packet_headers[4])
    flag = packet_headers[6]
    if message_size > MTU - header_size:
        while message_size > 0:
            fragment = packet_headers.copy()
            if message_size > MTU - header_size:
                # Modify the offset
                fragment[4] = str(offset)
                # Modify the size, size must be of length 8
                fragment[5] = str(MTU - header_size).zfill(8)
                # Modify the flag
                fragment[6] = "1"
                fragment.append(packet_message[0:MTU - header_size])
                fragments.append(fragment)
                packet_message = packet_message[MTU - header_size:]
                message_size = len(packet_message.encode())
                offset += MTU - header_size
            else:
                # Modify the offset
                fragment[4] = str(offset)
                # Modify the size, size must be of length 8
                fragment[5] = str(message_size).zfill(8)
                # Modify the flag
                fragment[6] = flag
                fragment.append(packet_message)
                fragments.append(fragment)
                message_size = 0
    else:
        fragments.append(packet)
    return fragments

#if the packet is not reassembled, return None
# format: [Dirección IP],[Puerto],[TTL],[ID],[Offset],[Tamaño],[FLAG],[mensaje]
def reassemble_IP_packet(fragments):
    fragments.sort(key=lambda x: int(x[4]))
    current_offset = 0
    current_message = ""
    current_size = 0
    if int(fragments[0][4]) != 0:
        return None
    if int(fragments[-1][6]) != 0:
        return None
    print(f"Reassembling {len(fragments)} fragments")
    print(f"First fragment: {fragments[0]}")
    print(f"Last fragment: {fragments[-1]}")
    for fragment in fragments:
        if int(fragment[4]) != current_offset:
            return None
        current_message += fragment[7]
        current_offset += int(fragment[5])
        current_size += int(fragment[5])
    packet_to_return = fragments[0][0:7]
    packet_to_return.append(current_message)
    packet_to_return[5] = str(current_size).zfill(8)
    return create_packet(packet_to_return)


def add_packet_to_dic(parsed_IP_packet):
    global dic_packets
    if parsed_IP_packet[3] in dic_packets:
        dic_packets[parsed_IP_packet[3]].append(parsed_IP_packet)
    else:
        dic_packets[parsed_IP_packet[3]] = [parsed_IP_packet]

# Router loop
while True:
    received, client_address = router_socket.recvfrom(1024)
    parsed_IP_packet = parse_packet(received)
    TTL = int(parsed_IP_packet[2])
    if TTL > 0:
        destiny_address = (parsed_IP_packet[0], int(parsed_IP_packet[1]))
        visited_max_size = get_visited_size(router_routes, destiny_address)
        destiny_route = check_routes(router_routes, destiny_address)
        if destiny_route != None:
            print(f"Resending packet {parsed_IP_packet} with final destination {destiny_address} from {(router_ip, router_port)} to {destiny_route}")
            parsed_IP_packet[2] = str(TTL - 1)
            fragmented_packet = fragment_IP_packet(parsed_IP_packet, destiny_route[1])
            for fragment in fragmented_packet:
                message_to_send = create_packet(fragment)
                router_socket.sendto(message_to_send.encode(), destiny_route[0])
        else:
            print(f"No route found for destination address {destiny_address} for packet {parsed_IP_packet}")
            add_packet_to_dic(parsed_IP_packet)
            if reassemble_IP_packet(dic_packets[parsed_IP_packet[3]]) != None:
                print(f"------------> Packet {parsed_IP_packet[3]} reassembled")
                print("Reassembled message: {}".format(reassemble_IP_packet(dic_packets[parsed_IP_packet[3]])))
    else:
        if check_routes(router_routes, destiny_address) == None:
            print(f"Packet {parsed_IP_packet} has reached its TTL limit")
            add_packet_to_dic(parsed_IP_packet)
            if reassemble_IP_packet(dic_packets[parsed_IP_packet[3]]) != None:
                print(f"------------> Packet {parsed_IP_packet[3]} reassembled")
                print("Reassembled message: {}".format(reassemble_IP_packet(dic_packets[parsed_IP_packet[3]])))
        print(f"received package {parsed_IP_packet} with TTL = 0")