import requests
from ipwhois import IPWhois

# Define the function to get geolocation information for an IP address
def get_geolocation(ip):
    try:
        # Send a request to the IP-API to lookup the address
        response = requests.get(f"http://ip-api.com/json/{ip}")
        geo_data = response.json()

        # Check if the response indicates success
        if geo_data['status'] == 'fail':
            return f"Geolocation failed: {geo_data['message']}"

        # Otherwise, return city and country information
        return f"{geo_data['city']}, {geo_data['country']}"
    except Exception as e:
        #Handle any errors during the API call
        return f"Geolocation lookup failed: {e}"

# Define the function to get WHOIS ownership data for an IP address
def get_whois_info(ip):
    try:
        #Perform a WHOIS lookup using the ipwhois library
        whois_data = IPWhois(ip).lookup_whois()
        return whois_data.get('asn_description', 'N/A') # Return ASN description or N/A
    except Exception as e:
        # Handle errors during WHOIS lookup
        return f"WHOIS lookup failed: {e}"

# Function to process a single IP address
def process_single_ip():
    ip_address = input("Enter the IP address to lookup: ").strip()
    if not ip_address:
        print("No IP address provided. Please re-enter address")
        return # Exit the function if no input is given
    
    # Get geolocation and WHOIS information
    geo_info = get_geolocation(ip_address)
    whois_info = get_whois_info(ip_address)

    # Print the results
    print("\nResults for the IP address:")
    print(f"IP Address: {ip_address}")
    print(f"Ownership Info: {whois_info}")
    print(f"Geolocation Info: {geo_info}")
    print("-" * 40)

# Function to process IP Addresses from a file
def process_ip_file():
    file_path = input("Enter the file path containing IP Addresses: ").strip()

    try:
        # Open the file and read each line
        with open(file_path, 'r') as file:
            ip_addresses = file.readlines()

        if not ip_addresses:
            print("The file is empty. Please provide a valid file.")
            return # Exit if the file is empty
        
        # Look through each IP address in the file
        for ip in ip_addresses:
            ip = ip.strip() # Sanitize data
            if not ip:
                continue # Skip empty lines

            # Get geolocation and WHOIS data for the IP's
            print(f"\nProcessing IP: {ip}")
            geo_info = get_geolocation(ip)
            whois_info = get_whois_info(ip)

            # Print results
            print(f"IP Address: {ip}")
            print(f"Ownership Info: {whois_info}")
            print(f"Geolocation Info: {geo_info}")
            print("-" * 40)

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Main function to provide user options and call the appropriate functions
def main():
    print("Welcome to my IP lookup tool!")
    print("1. Lookup a single IP address")
    print("2. Lookup IP addresses from a file")

    # Ask the user to choose which option
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '1':
        process_single_ip() # Call the single IP processing function
    elif choice == '2':
        process_ip_file() # Call the file processing function
    else:
        print("Invalid option. Please enter 1 or 2.")

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
