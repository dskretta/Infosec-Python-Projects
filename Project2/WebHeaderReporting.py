#Name: WebHeaderReporting.py
#Author: DSkretta
#License: MIT
#Github: https://github.com/dskretta/Infosec-Python-Projects/blob/main/Project2/WebHeaderReporting.py
#Description: This script checks various security headers for websites, from a provided file

import requests
import socket

# Manually split a url into scheme (http/https) and domain
def split_scheme_domain(url):
    if "://" in url:
        scheme, rest = url.split("://", 1)
    else:
        scheme = "http"
        rest = url
    domain = rest.split("/")[0]
    return scheme, domain

# Resolves the domain to its IP address
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Could not resolve"
    
def check_headers(url):
    scheme, domain = split_scheme_domain(url)
    ip = get_ip(domain)

    print(f"\n Checking {url}")
    print(f"IP: {ip}")


# Checks security-related headers for a single URL
    try:
        #Send GET request to fetch headers
        response = requests.get(url, timeout=5)
        headers = response.headers

        # HSTS, only matters if the url is HTTPS
        if scheme == "https":
            if "Strict-Transport-Security" in headers:
                print("HSTS is present")
            else:
                print("Missing Strict-Transport-Security")
        else:
            print("HTTP scheme - skipping HSTS check")
        
        # CSP
        if "Content-Security-Policy" in headers:
            print("Content-Security-Policy present")
        else:
            print("Missing Content-Security-Policy")

        # XFO
        if "X-Frame-Options" in headers:
            print("X-Frame-Options present")
        else:
            print("Missing X-Frame-Options")

        # Server
        if "Server" in headers:
            print(f" Server header: {headers['Server']}")
        else:
            print(" Server header not disclosed")
        
    except Exception as e:
        print(f"Error fetching {url}: {e}")

def process_url_list(file_path):
    with open(file_path, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            check_headers(url)

# Call the main function with your list of URLs
process_url_list("urls.txt")

