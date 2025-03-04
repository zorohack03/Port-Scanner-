# Stealth Network Scanner

This Python script implements a stealth network scanner capable of performing SYN scans with IP address spoofing (decoys) to obfuscate the origin of the scan. It provides various options to customize the scan, including port selection, decoy count, and timing templates.

## Features

* **SYN Scan:** Performs a SYN scan, which is less detectable than a full TCP connect scan.
* **IP Spoofing (Decoys):** Utilizes IP address spoofing to send scan packets from multiple IP addresses, making it harder to trace the origin of the scan.
* **Port Selection:** Allows scanning specific ports, a range of ports, top 10 ports, common ports, or all ports.
* **Timing Templates:** Offers predefined timing templates (T0, T1, T2) to control the scan speed and stealth level.
* **Custom Decoy Count:** Enables users to specify the number of decoy IP addresses to use.
* **Response Analysis:** Analyzes TCP responses to determine port status (open, closed, filtered).
* **Local IP Detection:** Automatically detects the local IP address for accurate response analysis.
* **Error Handling:** Includes error handling for invalid input and potential exceptions.

## Usage

```bash
python3 scanner.py <target_ip> [-p <ports>] [-d <number_of_decoys>] [-T<template>]

## Arguments

- `<target_ip>`: The IP address or hostname of the target system.
- `-p <ports>`: Specifies the ports to scan. Options:
  - `all`: Scan all ports (1-65535).
  - `top10`: Scan the top 10 common ports.
  - `common`: Scan a list of common ports.
  - `<port_number>`: Scan a single port (e.g., 80).
  - `<start>-<end>`: Scan a range of ports (e.g., 1-1024).
  - `<port1>,<port2>,<port3>`: Scan a comma-separated list of ports (e.g., 22,80,443).
- `-d <number_of_decoys>`: Specifies the number of decoy IP addresses to use (default: 6).
- `-T<template>`: Specifies the timing template. Options:
  - `-T0`: Paranoid (slowest, most stealthy).
  - `-T1`: Sneaky (faster, less stealthy).
  - `-T2`: Polite (default, balanced speed and stealth).

## Examples

### Scan the top 10 ports of `192.168.1.1`:
```bash
python3 scanner.py 192.168.1.1 -p top10


## Dependencies

- Python 3
- `socket` module (standard library)
- `struct` module (standard library)
- `random` module (standard library)
- `os` module (standard library)
- `fcntl` module (standard library)
- `time` module (standard library)
- `datetime` module (standard library)

## Important Notes

- This script requires **root privileges (sudo)** to send raw packets.
- **Use this tool responsibly and ethically. Unauthorized scanning of networks is illegal.**
- The effectiveness of **IP spoofing** may vary depending on network configurations and firewall rules.
- **Timing templates** influence the speed and stealth of the scan. Adjust them based on your needs and the target network.
- **Using a large number of decoys** can increase the chance of your scan being detected by network intrusion detection systems.
- **Filtered ports** may give false positives.
