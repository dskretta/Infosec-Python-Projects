import requests
from ipwhois import IPWhois
ip_address = input("Enter the IP address to lookup: ")

response = requests.get(f"http://ip-api.com/json/{ip_address}")
geo_data = response.json()

whois_data = IPWhois(ip_address).lookup_whois()


print("IP Address: ", ip_address)
print ("Ownership Info: ", whois_data['asn_description'])
print("Geolocation Info: ", geo_data['city'], geo_data['country'])
