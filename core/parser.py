from sniffer import NetworkSnifferr, PacketParser
import struct
import socket
import ipaddress

ip = '192.168.1.6'
port = 0

while True:
    net = NetworkSnifferr(ip)
    net.initialize_raw_socket(ip, port)
    net.start_capture()
    raw_bytes, address = net.packet_data

    if raw_bytes is not None:
        format_string = '> 12s B 2s 4s 4s'
        print("bytes size(needed):", struct.calcsize(format_string))
        print("bytes size:", len(raw_bytes))
        try:
            if len(raw_bytes) > 4:
                raw_bytes = raw_bytes[:4]
                
            if len(raw_bytes) < 4:
                readable_ip = "0.0.0.0" 
            else:
                readable_ip = str(ipaddress.IPv4Address(raw_bytes))

        except Exception as e:
            readable_ip = "0.0.0.0"
            print(f"DEBUG CRASH INFO -> Length: {len(raw_bytes)} bytes | Raw Hex: {raw_bytes.hex()}")
            readable_ip = socket.inet_ntoa(raw_bytes)
            unpacked_bytes = struct.unpack(format_string , raw_bytes)


        parsed_packet = PacketParser.parse_packet_layers(raw_bytes)
        if parsed_packet:
            print(f"[{parsed_packet['src_ip']}:{parsed_packet['src_port']}] -> "
                f"[{parsed_packet['dest_ip']}:{parsed_packet['dest_port']}] | "
                f"Protocol: {parsed_packet['protocol']}")
        
