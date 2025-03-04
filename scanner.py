#!/usr/bin/python3

import sys
import socket
import struct
import random
import os
import fcntl
import time
from datetime import datetime

# Top 10 ports
TOP_10_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445]

# 335 ports
COMMON_PORTS = [
    7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88, 102, 110, 113, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 177, 179, 201, 264, 318, 381, 382, 383, 389, 411, 412, 443, 445, 464, 465, 497, 500, 512, 513, 514,
    515, 520, 521, 540, 554, 546, 547, 560, 563, 587, 591, 593, 631, 636, 639, 646, 691, 860, 873, 902, 989, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1214, 1241, 1311, 1337, 1433, 1434, 1512, 1589, 1701, 1723, 1725,
    1741, 1755, 1812, 1813, 1863, 1985, 2000, 2002, 2049, 2082, 2083, 2100, 2222, 2302, 2483, 2484, 2745, 2967, 3050,
    3074, 3124, 3127, 3128, 3222, 3260, 3306, 3389, 3689, 3690, 3724, 3784, 3785, 4333, 4444, 4664, 4672, 4899, 5000,
    5001, 5004, 5005, 5050, 5060, 5190, 5222, 5223, 5432, 5500, 5554, 5631, 5632, 5800, 5900, 6000, 6001, 6112, 6129,
    6257, 6346, 6347, 6500, 6566, 6588, 6665, 6669, 6679, 6697, 6699, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888,
    6889, 6890, 6891, 6892, 6893, 6894, 6895, 6896, 6897, 6898, 6899, 6900, 6901, 6902, 6903, 6904, 6905, 6906, 6907,
    6908, 6909, 6910, 6911, 6912, 6913, 6914, 6915, 6916, 6917, 6918, 6919, 6920, 6921, 6922, 6923, 6924, 6925, 6926,
    6927, 6928, 6929, 6930, 6931, 6932, 6933, 6934, 6935, 6936, 6937, 6938, 6939, 6940, 6941, 6942, 6943, 6944, 6945,
    6946, 6947, 6948, 6949, 6950, 6951, 6952, 6953, 6954, 6955, 6956, 6957, 6958, 6959, 6960, 6961, 6962, 6963, 6964,
    6965, 6966, 6967, 6968, 6969, 6970, 6971, 6972, 6973, 6974, 6975, 6976, 6977, 6978, 6979, 6980, 6981, 6982, 6983,
    6984, 6985, 6986, 6987, 6988, 6989, 6990, 6991, 6992, 6993, 6994, 6995, 6996, 6997, 6998, 6999, 8000, 8080, 8086,
    8087, 8118, 8200, 8500, 8767, 8866, 9100, 9101, 9102, 9103, 9119, 9800, 9898, 9988, 9999, 10000, 10113, 10114,
    10115, 10116, 11371, 12035, 12036, 12345, 13720, 13721, 14567, 15118, 19226, 19638, 20000, 24800, 25999, 27015,
    27374, 28960, 31337, 33434
]

# Default 1000 ports
DEFAULT_1000_PORTS = list(range(1, 1001))

DEFAULT_DECOY_IPS = ["172.16.0.100", "127.0.0.1", "192.168.0.100", "10.0.0.100"]

TIMING_TEMPLATES = {
    "T0": {"retries": 10, "timeout": 315, "scan_delay": 5},
    "T1": {"retries": 10, "timeout": 10, "scan_delay": 0.015},
    "T2": {"retries": 10, "timeout": 10, "scan_delay": 0.4}
}

DEFAULT_TIMING_TEMPLATE = "T2"

def get_local_ip(target_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target_ip, 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except:
        return "127.0.0.1"

def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_ip_header(source_ip, dest_ip):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 40
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    ip_check = calculate_checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header

def build_tcp_header(source_ip, dest_ip, source_port, dest_port):
    seq_num = random.randint(0, 4294967295)
    ack_num = 0
    data_offset = 5
    reserved = 0
    tcp_flags = 0x02  # SYN
    window_size = 64240 + random.randint(-500, 500)
    if window_size < 0:
        window_size = 64240
    checksum = 0
    urg_pointer = 0
    tcp_header = struct.pack("!HHLLBBHHH",
                             source_port, dest_port, seq_num, ack_num,
                             (data_offset << 4) + reserved, tcp_flags,
                             window_size, checksum, urg_pointer)
    pseudo_header = struct.pack("!4s4sBBH",
                                 socket.inet_aton(source_ip), socket.inet_aton(dest_ip),
                                 0, socket.IPPROTO_TCP, len(tcp_header))
    checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack("!HHLLBBHHH",
                             source_port, dest_port, seq_num, ack_num,
                             (data_offset << 4) + reserved, tcp_flags,
                             window_size, checksum, urg_pointer)
    return tcp_header

def send_syn(target_ip, port, source_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        source_port = random.randint(1024, 65535)
        ip_header = build_ip_header(source_ip, target_ip)
        tcp_header = build_tcp_header(source_ip, target_ip, source_port, port)
        packet = ip_header + tcp_header
        sock.sendto(packet, (target_ip, 0))
        sock.close()
        return source_port
    except PermissionError:
        print("Use Sudo to run this Scan")
        sys.exit(1)

def receive_response(target_ip, port, expected_source_port, timeout, local_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.settimeout(timeout)
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            if not data:
                continue
            ip_header = data[0:20]
            try:
                ip_header_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
            except struct.error:
                continue
            ip_header_ihl = ip_header_unpacked[0] & 0x0F
            ip_header_length = ip_header_ihl << 2
            ip_source_addr = socket.inet_ntoa(ip_header_unpacked[8])
            ip_dest_addr = socket.inet_ntoa(ip_header_unpacked[9])
            tcp_header_offset = ip_header_length
            try:
                tcp_header = data[tcp_header_offset:tcp_header_offset+20] 
                tcp_header_unpacked = struct.unpack("!HHLLBBHHH", tcp_header[0:20])
            except struct.error:
                continue
            tcp_source_port = tcp_header_unpacked[0]
            tcp_dest_port = tcp_header_unpacked[1]
            if ip_dest_addr == local_ip and tcp_dest_port == expected_source_port and tcp_source_port == port:
                return data, addr
            else:
                continue
    except socket.timeout:
        return None, None
    except struct.error:
        return None, None
    finally:
        sock.close()

def scan_port(target_ip, port, num_decoys, retries, timeout, scan_delay):
    local_ip = get_local_ip(target_ip)
    decoy_ips = DEFAULT_DECOY_IPS + [local_ip, generate_random_ip()]
    sent_from_own_ip = False
    port_determined = False
    if num_decoys > len(decoy_ips):
        num_random_decoys = num_decoys - len(decoy_ips)
        for _ in range(num_random_decoys):
            decoy_ips.append(generate_random_ip())
    source_ips_to_scan = decoy_ips[:num_decoys]
    random.shuffle(source_ips_to_scan)
    for source_ip in source_ips_to_scan:
        expected_source_port = None
        if source_ip == local_ip:
            sent_from_own_ip = True
            for retry_attempt in range(retries):
                print(f"Sending SYN from local IP: {source_ip} to {target_ip}:{port} (Attempt {retry_attempt + 1})")
                expected_source_port = send_syn(target_ip, port, source_ip)
                response, addr = receive_response(target_ip, port, expected_source_port, timeout, local_ip)

                if response:
                    flags = response[33]
                    if flags & 0x12 == 0x12:
                        print(f"Port {port} is OPEN")
                        port_status = "OPEN"
                    elif flags & 0x14 == 0x14:
                        print(f"Port {port} is CLOSED (RST-ACK)")
                        port_status = "CLOSED (RST-ACK)"
                    elif flags & 0x04 == 0x04:
                        print(f"Port {port} is CLOSED (RST)")
                        port_status = "CLOSED (RST)"
                    else:
                        print(f"Port {port} is Unexpected response flags (hex): {hex(flags)}, FILTERED or CLOSED|FILTERED")
                        port_status = "FILTERED or CLOSED|FILTERED (Unexpected flags)"
                    port_determined = True
                    break
                else:
                    time.sleep(0.5)
        else:
            print(f"Sending decoy SYN from: {source_ip} to {target_ip}:{port} (No response expected)")
            send_syn(target_ip, port, source_ip)

        time.sleep(scan_delay)
    if not port_determined:
        if sent_from_own_ip:
            print(f"Port {port} is FILTERED or CLOSED|FILTERED (No valid response from local IP after {retries} retries)")
        else:
            print(f"Port {port} is  Likely FILTERED or CLOSED|FILTERED (No response from decoys, and no scan from local IP to verify)")

def scan_ports(target, ports, num_decoys, retries, timeout, scan_delay):
    print(f"Scanning Target: {target}")
    print(f"Time Started: {str(datetime.now())}\n")
    try:
        for port in ports:
            scan_port(target, port, num_decoys, retries, timeout, scan_delay)
    except KeyboardInterrupt:
        print("\nExit.")
        sys.exit(0)
    print("\nScan completed.")


def main():
    if len(sys.argv) < 2:
        print("Invalid amount of arguments")
        print("Syntax: python3 scanner.py <ip> [-p <ports>] [-d <number_of_decoys>] [-T<template>]")
        print("Timing templates: -T0 (Paranoid), -T1 (Sneaky), Default is T2 (Polite)")
        sys.exit()

    target = socket.gethostbyname(sys.argv[1])
    ports_to_scan = DEFAULT_1000_PORTS
    num_decoys = 6
    timing_template = TIMING_TEMPLATES[DEFAULT_TIMING_TEMPLATE]
    retries = timing_template["retries"]
    timeout = timing_template["timeout"]
    scan_delay = timing_template["scan_delay"]

    if "-T0" in sys.argv:
        timing_template = TIMING_TEMPLATES["T0"]
    elif "-T1" in sys.argv:
        timing_template = TIMING_TEMPLATES["T1"]

    retries = timing_template["retries"]
    timeout = timing_template["timeout"]
    scan_delay = timing_template["scan_delay"]

    if "-p" in sys.argv:
        try:
            port_arg = sys.argv[sys.argv.index("-p") + 1]
            if port_arg.lower() == "all":
                ports_to_scan = range(1, 65536)
            elif port_arg.lower() == "top10":
                ports_to_scan = TOP_10_PORTS
            elif port_arg.lower() == "common":
                ports_to_scan = COMMON_PORTS
            elif "-" in port_arg:
                start, end = map(int, port_arg.split("-"))
                ports_to_scan = range(start, end + 1)
            else:
                ports_to_scan = [int(p) for p in port_arg.split(",")]
        except:
            print("Invalid port.")
            sys.exit()

    if "-d" in sys.argv:
        try:
            num_decoys = int(sys.argv[sys.argv.index("-d") + 1])
            if num_decoys < 1:
                print("Number of decoys must be at least 1. Using default (6).")
                num_decoys = 6
        except ValueError:
            print("Invalid decoy number. Using default (6).")

    try:
        scan_ports(target, ports_to_scan, num_decoys, retries, timeout, scan_delay)
    except KeyboardInterrupt:
        print("\nExit")
        sys.exit(0)


if __name__ == "__main__":
    main()
