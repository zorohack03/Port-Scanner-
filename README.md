# Python Port Scanner

This Python script is a simple port scanner that checks all ports on a target host to determine if they are open or closed. It uses the `socket` module to attempt connections to each port and reports which ports are open.

## Features

- Scans all 65535 ports on a specified target host.
- Uses the `socket` module for network connections.
- Sets a timeout of 1 second for each connection attempt to avoid long delays.
- Provides detailed output including the target host and the time the scan started.
- Handles common exceptions such as keyboard interruption, hostname resolution errors, and connection errors gracefully.

## Requirements

- Python 3
- `socket` module (included with Python standard library)
- `datetime` module (included with Python standard library)

## Usage

1. Clone the repository or download the script.

2. Open a terminal and navigate to the directory containing the script.

3. Run the script with the following syntax:
   ```sh
   python3 scanner.py <target_ip_or_hostname>

## Output

The script will output the following information:

- The target being scanned
- The time the scan started
- A list of open ports (if any)

## Handling Exceptions

The script includes exception handling for:

- **KeyboardInterrupt:** Exits the program if the user interrupts the execution (e.g., by pressing Ctrl+C).
- **socket.gaierror:** Informs the user if the hostname could not be resolved.
- **socket.error:** Informs the user if the connection to the server could not be established.

## Notes

- **Socket Timeout:** The script sets a default timeout of 1 second for each socket operation to avoid long waits.
- **Port Range:** The script scans all ports from 1 to 65535.
- **Exception Handling:** The script handles exceptions to provide useful error messages and ensure a clean exit.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.


