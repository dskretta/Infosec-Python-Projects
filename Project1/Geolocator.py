#Name: Geolocator.py
#Author: DSkretta
#License: MIT
#Github: https://github.com/dskretta/Infosec-Python-Projects/blob/main/Project1/Geolocator.py
#Description: This script runs IP addresses through the ip-api.com API for geolocation to print the owner and location

import requests
from ipwhois import IPWhois
import ipaddress
import argparse

# Function to get geolocation information for an IP address
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        geo_data = response.json()
        if geo_data['status'] == 'fail':
            return f"Geolocation failed: {geo_data['message']}"
        return f"{geo_data['city']}, {geo_data['country']}"
    except Exception as e:
        return f"Geolocation lookup failed: {e}"

# Function to get WHOIS ownership information for an IP address
def get_whois_info(ip):
    try:
        whois_data = IPWhois(ip).lookup_whois()
        return whois_data.get('asn_description', 'N/A')
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# Function to process a single IP address
def process_single_ip(ip):
    print(f"\nProcessing IP Address: {ip}")
    geo_info = get_geolocation(ip)
    whois_info = get_whois_info(ip)
    print(f"IP Address: {ip}")
    print(f"Ownership Info: {whois_info}")
    print(f"Geolocation Info: {geo_info}")
    print("-" * 40)

# Function to process a CIDR range
def process_cidr(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        print(f"\nProcessing CIDR range: {cidr}")
        for ip in network:
            process_single_ip(str(ip))
    except ValueError as e:
        print(f"Invalid CIDR notation: {cidr}. Error: {e}")

# Function to read through a mixed file of IPs and CIDR ranges
def process_mixed_file(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for line in lines:
            input_data = line.strip()
            if not input_data:
                continue # Skip any empty lines

            if '/' in input_data: # CIDR range
                process_cidr(input_data)
            else: # Single IP
                process_single_ip(input_data)

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="IP address and CIDR range Lookup Tool")
    parser.add_argument(
        "-c", "--check", help="Specify a single IP address or CIDR range to lookup", type=str
    )
    parser.add_argument(
        "-f", "--file", help="Specify a file containing IP addresses and CIDR ranges to lookup", type=str
    )

    args = parser.parse_args()

    if args.check:
        input_data = args.check.strip()
        if '/' in input_data: # CIDR range
            process_cidr(input_data)
        else: # Single IP address
            process_single_ip(input_data)
    elif args.file:
        process_mixed_file(args.file.strip())
    else:
        print("Error: Please specify either -c for a single lookup. or -f for a file lookup.")
        parser.print_help()

# Run the main function
if __name__ == "__main__":
    main()
