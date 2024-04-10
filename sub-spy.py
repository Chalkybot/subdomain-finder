#!/bin/python
from bs4 import BeautifulSoup
import requests
import sys
import re
import socket

def resolve_domain(domain_name):
    addr_info = socket.getaddrinfo(domain_name, None, socket.AF_INET)
    ip_addresses = list(set([addr[4][0] for addr in addr_info]))
    return ip_addresses

def parse_args(arguments):
    url_regex = r'(https?://)?(www\.)?'
    domains = [re.sub(url_regex, "", argument) for argument in arguments]
    return domains

# Cheap way:
def parse_crt(response, root_domain):
    regex = r'([A-z0-9]+\.[A-z0-9]+\.[A-z0-9]+)'
    domains = re.findall(regex, response)
    filtered_domains = list(set([domain for domain in domains if root_domain in domain]))
    return filtered_domains

def query_crt(domain):
    r = requests.get("https://crt.sh/?Identity=" + domain)
    f = parse_crt(r.text, domain)
    for domain in f:
        print(f"Domain: {domain} -> {resolve_domain(domain)}")

def main():
    domains = parse_args(sys.argv[1:])
    query_crt(domains[0])

if __name__ == '__main__':
    main()

