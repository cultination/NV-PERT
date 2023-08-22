import socket
import os
import ping3
import sys
import whois
import requests
import re
from datetime import datetime
from colorama import init, Fore, Style

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


def main():
    intro = r"""
  _   ___      __  _____  ______ _____ _______       
 | \ | \ \    / / |  __ \|  ____|  __ \__   __|    
 |  \| |\ \  / /  | |__) | |__  | |__) | | | 
 | . ` | \ \/ /   |  ___/|  __| |  _  /  | | 
 | |\  |  \  /    | |    | |____| | \ \  | |
 |_| \_|   \/     |_|    |______|_|  \_\ |_|
                                                                                                   
    """
    print(Fore.CYAN + intro)

    while True:
        target = input(Fore.YELLOW + "Enter target IP or domain (or 'exit' to quit): ")
        if target.lower() == "exit":
            print(Fore.RED + "Exiting...")
            sys.exit()

        if not validate_ip(target):
            print(
                Fore.RED
                + "Invalid IP or domain format. Please enter a valid IP or domain."
            )
            continue

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
        print("11. Return to main menu")

        choice = input(Fore.YELLOW + "Enter your choice: ")

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
                print(
                    Fore.GREEN + f"City: {city}, Region: {region}, Country: {country}"
                )
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
            print(Fore.YELLOW + "Returning to main menu...")
        else:
            print(Fore.RED + "Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()