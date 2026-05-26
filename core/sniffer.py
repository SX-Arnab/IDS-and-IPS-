import socket
import sys
import os
from parser import process_packet, flush_buffer

if os.name != 'nt':
    sys.exit("Error: This script is explicitly configured for Windows systems.")

log_dir = "storage"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

def get_active_interface_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "0.0.0.0"
    finally:
        s.close()
    return ip

host_ip = get_active_interface_ip()
if host_ip == "0.0.0.0":
    sys.exit("Error: Could not determine an active network interface.")

try:
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    raw_socket.bind((host_ip, 0))
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
except PermissionError:
    sys.exit("Error: Administrator privileges are required. Run CMD/PowerShell as Administrator.")
except Exception as e:
    sys.exit(f"Windows Driver Hook Failed on {host_ip}: {e}")

packet_count = 0

try:
    while True:
        raw_data, _ = raw_socket.recvfrom(65535)
        packet_count += 1
        process_packet(raw_data, packet_count)

except KeyboardInterrupt:
    flush_buffer()
    try:
        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except:
        pass
    sys.exit("\nSniffer stopped gracefully.")