from sniffer import NetworkSnifferr
import struct

ip = '192.168.56.1'
port = 0


net = NetworkSnifferr(ip)
net.initialize_raw_socket(ip, port)
net.start_capture()
raw_bytes, address = net.packet_data

if raw_bytes is not None:
    format_string = '> 12s B 2s 4s 4s'
    unpacked_bytes = struct.unpack(format_string , raw_bytes)
    with open(r'core\logs.txt', 'w') as f:
        f.write(unpacked_bytes)
    print("Successfully written to logs")