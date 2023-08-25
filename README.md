# NV Pert IP Multi Tool

Welcome to NV Pert IP Multi Tool! This tool provides a variety of network-related functionalities to help you analyze and troubleshoot network connections.

## Features

- DNS Lookup
- Ping
- Traceroute
- Whois Lookup
- Reverse DNS Lookup
- DNS Zone Transfer
- GeoIP Lookup
- Banner Grabbing
- TCP Traceroute
- HTTP Header Analysis
- Vulnerability Scan (*requires `nmap` tool*)

## Installation

1. Clone this repository to your local machine.
2. Navigate to the repository directory.
3. Install the required Python packages using the following command: `pip install -r requirements.txt`
4. Install `nmap` on your system as path to enable the Vulnerability Scan feature. You can download it from [https://nmap.org/download.html](https://nmap.org/download.html) and follow the installation instructions for your operating system.

## Usage

1. Run the script.
2. Follow the on-screen prompts to choose and execute different network functionalities, including Vulnerability Scan.
3. For the Vulnerability Scan, make sure `nmap` is installed, and the tool will use it to perform the scan.

## Example

Here's an example of how to run the tool and perform a DNS lookup:

1. Run the script.
2. Enter the target IP or domain when prompted.
3. Choose the option for DNS Lookup.
4. The tool will display the IP address associated with the entered domain.

## Contribution

Contributions are welcome! If you have suggestions or want to add new features, feel free to open an issue or create a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Enjoy using NV Pert IP Multi Tool for your network analysis needs!
