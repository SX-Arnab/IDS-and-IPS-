import os
import datetime
from ..core.sniffer import PacketParser, NetworkSnifferr
class IDSLogger:
    def __init__(self, log_dir= r"storage\logs", filename="traffic.log"):
        # 1. Store the paths as instance variables
        self.log_dir = log_dir
        self.log_path = os.path.join(log_dir, filename)
        
        # 2. FIX/PREVENT CRASH: Create the folder if it doesn't exist yet
        # exist_ok=True prevents an error if the directory already exists
        os.makedirs(self.log_dir, exist_ok=True)

    def log_packet(self, src_ip, dst_ip, protocol, length):
        # 3. Generate a precise timestamp for forensic tracking
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # 4. Format the entry as a standardized, scannable log string
        log_entry = (
            f"[{timestamp}] "
            f"SRC: {src_ip} -> DST: {dst_ip} | "
            f"PROTO: {protocol} | SIZE: {length} bytes\n"
        )
        
        # 5. Open file in APPEND mode ('a') so older records aren't erased
        with open(self.log_path, "a") as log_file:
            log_file.write(log_entry)


network = PacketParser('192.168.1.5')
src_ip = network.source_ip
des_ip = network.destination_ip

protocol_type = network.protocol_type

src_port = network.source_port
des_port = network.destination_port

if __name__ == "__main__":
    # Test the logger structure independently
    # This will create a 'storage/traffic.log' file if you use "storage"
    logger = IDSLogger(log_dir= r"IDS-and-IPS-\storage\logs") 
    logger.log_packet(src_ip, des_ip, protocol_type, 64)
    print("Test packet written to storage/traffic.log successfully!")