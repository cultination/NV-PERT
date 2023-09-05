import socket
import os
import ping3
import sys
import whois
import requests
import re
import nmap
from datetime import datetime
from colorama import init, Fore, Back, Style



init(autoreset=True)


def validate_ip(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)


def dns_lookup(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return Fore.RED + "Unable to resolve the domain name."


def ping(target):
    try:
        response_time = ping3.ping(target)
        if response_time is not None:
            return f"Ping successful. Response time: {response_time:.2f} ms"
        else:
            return Fore.RED + "Ping failed."
    except Exception as e:
        return Fore.RED + f"Ping error: {e}"


def scan_ports(target, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def reverse_dns_lookup(ip):
    try:
        domain_name = socket.getfqdn(ip)
        return domain_name
    except Exception as e:
        return Fore.RED + f"Reverse DNS lookup error: {e}"


def dns_zone_transfer(domain):
    try:
        zone_transfer_output = os.popen(f"nslookup -type=AXFR {domain}").read()
        return zone_transfer_output
    except Exception as e:
        return Fore.RED + f"DNS zone transfer error: {e}"


def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        city = data.get("city", "Unknown")
        region = data.get("region", "Unknown")
        country = data.get("country", "Unknown")
        return city, region, country
    except Exception as e:
        return Fore.RED + f"GeoIP lookup error: {e}"


def banner_grabbing(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        banner = sock.recv(1024).decode("utf-8").strip()
        sock.close()
        return banner
    except Exception as e:
        return Fore.RED + f"Banner grabbing error: {e}"


def tcp_traceroute(target):
    try:
        if sys.platform == "win32":
            tracert_output = os.popen(f"tracert {target}").read()
        else:
            tracert_output = os.popen(f"traceroute -T {target}").read()
        return tracert_output
    except Exception as e:
        return Fore.RED + f"TCP traceroute error: {e}"


def http_header_analysis(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return headers  # This should be a dictionary
    except Exception as e:
        return Fore.RED + f"HTTP header analysis error: {e}"


def whois_lookup(target):
    try:
        whois_info = whois.whois(target)
        return str(whois_info)
    except Exception as e:
        return Fore.RED + f"Whois lookup error: {e}"

def vulnerability_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-Pn -p- -T4")
        return nm.csv()
    except nmap.PortScannerError as e:
        return f"Vulnerability scanning failed: {e}"
    except Exception as e:
        return f"An error occurred: {e}"

def ip_to_binary(ip):
    return '.'.join(format(int(x), '08b') for x in ip.split('.'))

def ip_to_decimal(ip):
    return sum(int(byte) << ((3 - i) * 8) for i, byte in enumerate(ip.split('.')))

def subnet_calculator(ip, mask):
    # Convert strings to binary
    ip_bin = ''.join(format(int(x), '08b') for x in ip.split('.'))
    mask_bin = ''.join(format(int(x), '08b') for x in mask.split('.'))
    
    # Compute network and broadcast
    network_bin = ''.join(ip_bit if mask_bit == '1' else '0' for ip_bit, mask_bit in zip(ip_bin, mask_bin))
    broadcast_bin = ''.join(ip_bit if mask_bit == '1' else '1' for ip_bit, mask_bit in zip(ip_bin, mask_bin))
    
    # Convert binaries back to strings
    network = '.'.join(str(int(network_bin[i:i+8], 2)) for i in range(0, 32, 8))
    broadcast = '.'.join(str(int(broadcast_bin[i:i+8], 2)) for i in range(0, 32, 8))
    
    return network, broadcast



def display_gradient_text():
    red = Fore.RED
    
    text = [
        '----------------------------------',
        '             NV v1.2              ',
        '----------------------------------'
    ]
    
    for line in text:
        print(red + line + Fore.RESET)

def main():
    display_gradient_text()

    while True:
        target = input(Fore.YELLOW + "Enter target IP or domain (or 'exit' to quit): ")
        
        if target.lower() == "exit":
            print(Fore.RED + "Exiting...")
            sys.exit()

        while True:
            print("\nSelect an option:")
            print("1. DNS Lookup")
            print("2. Ping")
            print("3. Traceroute")
            print("4. Whois Lookup")
            print("5. Reverse DNS Lookup")
            print("6. DNS Zone Transfer")
            print("7. GeoIP Lookup")
            print("8. Banner Grabbing")
            print("9. TCP Traceroute")
            print("10. HTTP Header Analysis")
            print("11. Vulnerability Scan")
            print("12. Convert IP to Binary")
            print("13. Convert IP to Decimal")
            print("14. Subnet Calculator")
            print("15. Open Ports Scan")
            print("16. Return to main menu")


            choice = input(Fore.YELLOW + "Enter your choice (or 'exit' to return): " + Fore.RESET)

            if choice.lower() == "exit":
                break

            if choice == "1":
                ip = dns_lookup(target)
                print(Fore.GREEN + f"IP address: {ip}")
            elif choice == "2":
                ping_result = ping(target)
                print(ping_result)
            elif choice == "3":
                traceroute_output = tcp_traceroute(target)
                print(traceroute_output)
            elif choice == "4":
                whois_output = whois_lookup(target)
                print(whois_output)
            elif choice == "5":
                reverse_dns_result = reverse_dns_lookup(target)
                print(Fore.GREEN + f"Domain name: {reverse_dns_result}")
            elif choice == "6":
                dns_zone_transfer_output = dns_zone_transfer(target)
                print(dns_zone_transfer_output)
            elif choice == "7":
                geoip_result = geoip_lookup(target)
                if isinstance(geoip_result, tuple) and len(geoip_result) == 3:
                    city, region, country = geoip_result
                    print(Fore.GREEN + f"City: {city}, Region: {region}, Country: {country}")
                else:
                    print(geoip_result)
            elif choice == "8":
                port = int(input(Fore.YELLOW + "Enter port: "))
                banner = banner_grabbing(target, port)
                print(Fore.GREEN + f"Banner: {banner}")
            elif choice == "9":
                tcp_traceroute_output = tcp_traceroute(target)
                print(tcp_traceroute_output)
            elif choice == "10":
                url = input(Fore.YELLOW + "Enter URL for HTTP Header Analysis: ")
                headers = http_header_analysis(url)
                print(Fore.GREEN + "HTTP Headers:")
                for key, value in headers.items():
                    print(f"{key}: {value}")
            elif choice == "11":
                print(Fore.YELLOW + "Performing Vulnerability Scan...")
                vulnerability_result = vulnerability_scan(target)
                print(Fore.GREEN + "Vulnerability Scan Results:")
                print(vulnerability_result)
            elif choice == "12":
                print(Fore.GREEN + "Binary Representation: " + ip_to_binary(target))
            elif choice == "13":
                print(Fore.GREEN + "Decimal Representation: " + str(ip_to_decimal(target)))
            elif choice == "14":
                mask = input(Fore.YELLOW + "Enter the subnet mask (e.g. 255.255.255.0): ")
                network, broadcast = subnet_calculator(target, mask)
                print(Fore.GREEN + f"Network Address: {network}\nBroadcast Address: {broadcast}")
            elif choice == "15":
                start_port = int(input(Fore.YELLOW + "Enter the starting port (e.g. 1): "))
                end_port = int(input(Fore.YELLOW + "Enter the ending port (e.g. 65535): "))
    
                print(Fore.YELLOW + "Scanning for open ports...")
                open_ports = scan_ports(target, start_port, end_port)
    
                if open_ports:
                    print(Fore.GREEN + "Open Ports Details:")
                    for port in open_ports:
                        # Service Name
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "Unknown service"
            
                        # Banner Grabbing
                        banner = banner_grabbing(target, port)
            
                        # Common Vulnerabilities (Just an example, can be expanded)
                        vulnerabilities = ""
                        if "Apache" in banner:
                            vulnerabilities = "Potential vulnerabilities associated with Apache. Check regularly for updates."
                        elif "OpenSSH" in banner and "7.2" in banner:
                            vulnerabilities = "Potential vulnerabilities with OpenSSH 7.2. Consider updating."

                        print(f"Port {port} : {service}")
                        print(f"Banner: {banner}")
                        if vulnerabilities:
                            print(Fore.RED + f"Note: {vulnerabilities}")
                        print("-" * 50)
                else:
                    print(Fore.RED + "No open ports found within the specified range.")

            elif choice == "16":
                print(Fore.YELLOW + "Returning to main menu...")
                break
            else:
                print(Fore.RED + "Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()
