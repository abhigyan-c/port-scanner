# Network Scanner

A multi-functional network scanner built with Python and Scapy, featuring a graphical user interface (GUI) using Tkinter. This tool supports various types of network scans such as SYN, TCP Connect, UDP, ACK, Window, FIN, Xmas, and Null scans.

## Features

- **SYN Scan**: Sends SYN packets to detect open ports.
- **TCP Connect Scan**: Establishes a full TCP connection to detect open ports.
- **UDP Scan**: Sends UDP packets to detect open ports.
- **ACK Scan**: Determines if ports are filtered by a firewall.
- **Window Scan**: Uses TCP window size to determine open ports.
- **FIN Scan**: Sends FIN packets to detect open ports.
- **Xmas Scan**: Sends TCP packets with FIN, PSH, and URG flags set to detect open ports.
- **Null Scan**: Sends TCP packets with no flags set to detect open ports.
- **Real-time Progress**: Displays the current port being scanned.
- **Stop Scan**: Allows stopping the scan process mid-way.

## Prerequisites

- Python 3.x
- Scapy
- Tkinter (usually included with Python installations)

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/abhigyan-c/port-scanner.git
   cd port-scanner
2. Install the required packages:
   ```sh
   pip install -r requirements.txt
3. Run the script:
   ```sh
   sudo python port_scan.py
## Usage

1. **Enter the Target IP**: Specify the IP address of the target machine.
2. **Enter the Port Range**: Provide the port range in one of the following formats:
   - **Single Port**: e.g., `22`
   - **Comma-Separated Ports**: e.g., `22,80,443`
   - **Port Range**: e.g., `0-1024`
3. **Select Scan Type**: Choose the type of scan from the drop-down menu, which includes:
   - SYN Scan
   - TCP Connect Scan
   - UDP Scan
   - ACK Scan
   - Window Scan
   - FIN Scan
   - Xmas Scan
   - Null Scan
4. **Start Scan**: Click the "Start Scan" button to begin scanning the specified ports.
5. **Stop Scan**: If needed, click the "Stop Scan" button to halt the scanning process.
6. **View Results**: The results of the scan will be displayed in the GUI, showing open or filtered ports based on the selected scan type.

## Scan Types

- **SYN Scan**: Detects open ports by sending SYN packets and waiting for SYN/ACK responses. Ports that respond with SYN/ACK are considered open.
- **TCP Connect Scan**: Establishes a full TCP connection to detect open ports. Ports that successfully complete the TCP handshake are considered open.
- **UDP Scan**: Detects open UDP ports by sending UDP packets and waiting for responses. Ports with no response or specific responses are considered open.
- **ACK Scan**: Determines if ports are filtered by sending ACK packets. Ports that do not respond or respond with an RST are considered filtered or unfiltered.
- **Window Scan**: Uses TCP window size to detect open ports. Ports with a non-zero window size are considered open.
- **FIN Scan**: Sends FIN packets to detect open ports. Ports that do not respond or respond with an RST are considered open.
- **Xmas Scan**: Sends TCP packets with FIN, PSH, and URG flags set to detect open ports. Ports that do not respond or respond with an RST are considered open.
- **Null Scan**: Sends TCP packets with no flags set to detect open ports. Ports that do not respond or respond with an RST are considered open.

## Code Overview

### Main Script

The main script, `network_scanner.py`, sets up a Tkinter GUI and defines functions for each scan type. Key components include:

- **GUI Setup**: Input fields for target IP, port range, and scan type.
- **Scan Functions**: Functions for each scan type (e.g., `SynScan`, `TcpConnectScan`, `UdpScan`).
- **Scan Execution**: A function to start the scan in a separate thread and update progress in the GUI.
- **Scan Interruption**: A function to stop the scan by setting a flag.

### Functions

- **SynScan**: Sends SYN packets and checks for SYN/ACK responses.
- **TcpConnectScan**: Establishes TCP connections and checks for successful connections.
- **UdpScan**: Sends UDP packets and checks for responses.
- **AckScan**: Sends ACK packets and checks for no response or RST packets.
- **WindowScan**: Sends ACK packets and checks the TCP window size.
- **FinScan**: Sends FIN packets and checks for no response or RST packets.
- **XmasScan**: Sends packets with FIN, PSH, and URG flags and checks for no response or RST packets.
- **NullScan**: Sends packets with no flags and checks for no response or RST packets.
