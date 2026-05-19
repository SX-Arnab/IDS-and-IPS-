import os
import socket
import struct

class NetworkSnifferr:
    def __init__(self, host_ip) -> None:
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

        if len(packet_data) < 20:
            return None

        ip_header_rwa = packet_data[0:20]
        ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header_rwa)
        
        version_ihl = ip_fields[0]
        ihl = version_ihl & 0x0F
        ip_header_length = ihl * 4  
        

        protocol_type = ip_fields[6]
        source_ip = socket.inet_ntoa(ip_fields[8])
        destination_ip = socket.inet_ntoa(ip_fields[9])
        

        source_port = None
        destination_port = None
        payload = packet_data[ip_header_length:]


        if protocol_type == 6:  # TCP
            if len(payload) >= 20:
                tcp_header_raw = packet_data[ip_header_length : ip_header_length + 20]
                tcp_fields = struct.unpack("!HHLLBBHHH", tcp_header_raw)
                
                source_port = tcp_fields[0]
                destination_port = tcp_fields[1]
                
                tcp_ihl = (tcp_fields[4] >> 4) * 4
                payload = payload[tcp_ihl:]

        elif protocol_type == 17:  # UDP
            if len(payload) >= 8:
                udp_header_raw = packet_data[ip_header_length : ip_header_length + 8]
                udp_fields = struct.unpack("!HHHH", udp_header_raw)
                
                source_port = udp_fields[0]
                destination_port = udp_fields[1]
                payload = payload[8:]  # UDP headers are always 8 bytes

        return {
            "src_ip": source_ip,
            "dest_ip": destination_ip,
            "protool": protocol_type,
            "src_port": source_port,
            "dest_port": destination_port,
            "payload": payload
        }