import os
import socket

class NetwrokSnifferr:
    def __init__(self, host_ip: str) -> None:
        self.host_ip = host_ip
        self.socekt = None

    def initialize_socket(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
        self.ip = ip
        self.port = port
        client, add = sock.bind(ip, port)

    def initialize_raw_socket(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.ip = ip
        self.port = port
        sock.bind(ip, port)
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)