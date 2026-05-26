import os
import socket
import struct

class NetworkSnifferr:
    def __init__(self, host_ip):
        self.host_ip = host_ip
        self.sock = None

    def initialize_raw_socket(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.ip = ip
        self.port = port
        self.sock = sock
        sock.bind((ip, port))
        sock.ioctl(socket.SIO_RCVALL, 1)
        
    def start_capture(self):
        print("PRESS CTRL+C TO EXIT")
        try:
            count = 0
            while True:
                self.packet_data = self.sock.recvfrom(65535)
                print(self.packet_data)
                
                count += 1
                if count >= 10:
                    break
        except KeyboardInterrupt as e:
            print("EXited Successfully")    

ip = '192.168.56.1'
port = 0


if __name__ == "__main__":
    net = NetworkSnifferr(ip)
    net.initialize_raw_socket(ip, port)
    net.start_capture()

class PacketParser:
    @staticmethod
    def parse_packet_layers(packet_data: bytes) -> dict:
        first_byte = packet_data[0]
        if (first_byte >> 4) == 4:
            ip_offset = 0 
        else:
            ip_offset = 14 
        if len(packet_data) < (ip_offset + 20):
            return None

        ip_header_raw = packet_data[ip_offset : ip_offset + 20]
        ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header_raw)
        
        raw_src_ip = packet_data[ip_offset + 12 : ip_offset + 16]
        raw_dest_ip = packet_data[ip_offset + 16 : ip_offset + 20]
        print(f"DEBUG: Data length is {len(raw_src_ip)} bytes | Hex representation: {raw_src_ip.hex()}")

        source_ip = socket.inet_ntoa(raw_src_ip)
        destination_ip = socket.inet_ntoa(raw_dest_ip)

        version_ihl = ip_fields[0]
        ihl = version_ihl & 0x0F
        ip_header_length = ip_offset + (ihl * 4)  
        
        protocol_type = ip_fields[6]
        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol_type, f"RAW({protocol_type})")
        
        source_port = "N/A"
        destination_port = "N/A"
        payload = packet_data[ip_header_length:]

        if protocol_type == 6 and len(payload) >= 20:  
            tcp_fields = struct.unpack("!HHLLBBHHH", packet_data[ip_header_length : ip_header_length + 20])
            source_port = tcp_fields[0]
            destination_port = tcp_fields[1]


        elif protocol_type == 17 and len(payload) >= 8:  
            udp_fields = struct.unpack("!HHHH", packet_data[ip_header_length : ip_header_length + 8])
            source_port = udp_fields[0]
            destination_port = udp_fields[1]

        return {
            "src_ip": source_ip,
            "dest_ip": destination_ip,
            "protocol": protocol_name,
            "src_port": source_port,
            "dest_port": destination_port,
            "payload": payload
        }
    
