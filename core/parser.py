import struct
import ipaddress
from datetime import datetime

log_path = r"storage\logs.txt"
packet_buffer = []
flush_threshold = 20

def parse_ip_header(data):
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ttl = ip_header[5]
    proto = ip_header[6]
    src_ip = str(ipaddress.IPv4Address(ip_header[8]))
    dst_ip = str(ipaddress.IPv4Address(ip_header[9]))
    return ttl, proto, src_ip, dst_ip, data[ihl:]

def parse_tcp_header(data):
    tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq = tcp_header[2]
    ack = tcp_header[3]
    flags = tcp_header[5]
    data_offset = (tcp_header[4] >> 4) * 4
    return src_port, dst_port, seq, ack, flags, data[data_offset:]

def parse_udp_header(data):
    udp_header = struct.unpack("!HHHH", data[:8])
    src_port = udp_header[0]
    dst_port = udp_header[1]
    length = udp_header[2]
    return src_port, dst_port, length, data[8:]

def generate_hex_ascii_dump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_part += " " * (48 - len(hex_part))
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part[:24]} {hex_part[24:]}  {ascii_part}")
    return "\n".join(lines)

def flush_buffer():
    global packet_buffer
    if packet_buffer:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("".join(packet_buffer))
        packet_buffer.clear()

def process_packet(raw_data, count):
    global packet_buffer
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    try:
        ttl, ip_proto, src_ip, dst_ip, l4_data = parse_ip_header(raw_data)
    except:
        return

    log_entry = [
        "=" * 80 + "\n",
        f"No. {count} | Time: {timestamp} | Length: {len(raw_data)} bytes\n",
        f"ROUTE: {src_ip} -> {dst_ip} | TTL: {ttl}\n",
        "-" * 80 + "\n",
        "INTERNET LAYER (IPv4)\n",
        f"  |- TTL             : {ttl}\n",
        f"  |- Protocol ID     : {ip_proto}\n"
    ]

    payload = b""

    if ip_proto == 6:
        try:
            src_port, dst_port, seq, ack, flags, payload = parse_tcp_header(l4_data)
            log_entry.append("TRANSPORT LAYER (TCP)\n")
            log_entry.append(f"  |- Source Port     : {src_port}\n")
            log_entry.append(f"  |- Dest Port       : {dst_port}\n")
            log_entry.append(f"  |- Seq / Ack       : {seq} / {ack}\n")
            log_entry.append(f"  |- Raw Flags Byte  : 0x{flags:02x}\n")
        except:
            pass
    elif ip_proto == 17:
        try:
            src_port, dst_port, udp_len, payload = parse_udp_header(l4_data)
            log_entry.append("TRANSPORT LAYER (UDP)\n")
            log_entry.append(f"  |- Source Port     : {src_port}\n")
            log_entry.append(f"  |- Dest Port       : {dst_port}\n")
            log_entry.append(f"  |- UDP Length      : {udp_len}\n")
        except:
            pass
    else:
        log_entry.append(f"TRANSPORT LAYER (Other Layer 4 Protocol)\n")
        payload = l4_data

    if payload:
        log_entry.append("\nPAYLOAD HEX & ASCII DUMP:\n")
        log_entry.append(generate_hex_ascii_dump(payload) + "\n")

    log_entry.append("=" * 80 + "\n\n")
    
    packet_buffer.append("".join(log_entry))
    
    if len(packet_buffer) >= flush_threshold:
        flush_buffer()