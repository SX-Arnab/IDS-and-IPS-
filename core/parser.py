from sniffer import NetworkSnifferr, PacketParser
import struct
import socket

ip = '192.168.56.1'
port = 0


net = NetworkSnifferr(ip)
net.initialize_raw_socket(ip, port)
net.start_capture()
raw_bytes, address = net.packet_data

if raw_bytes is not None:
    format_string = '> 12s B 2s 4s 4s'
    print("bytes size(needed):", struct.calcsize(format_string))
    print("bytes size:", len(raw_bytes))
    readable_ip = socket.inet_ntoa(raw_bytes)
    unpacked_bytes = struct.unpack(format_string , raw_bytes)


    parsed_packet = PacketParser.parse_packet_layers(raw_bytes)
    if parsed_packet:
        print(f"[{parsed_packet['src_ip']}:{parsed_packet['src_port']}] -> "
              f"[{parsed_packet['dest_ip']}:{parsed_packet['dest_port']}] | "
              f"Protocol: {parsed_packet['protocol']}")