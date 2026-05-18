import os
import socket

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
