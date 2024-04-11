import requests
import socket
import json
import sys
import re

class SubDomain:
    def __init__(self, domain, padding):
        self.domain_name = domain
        self.ip_addresses = self.resolve_domain()
        self.padding = padding
        self.parsed_ips = {}

    def resolve_domain(self):
        try:
            # DNS query returning every IP.
            addr_info = socket.getaddrinfo(self.domain_name, None, socket.AF_INET)
            ip_addresses = list(set([addr[4][0] for addr in addr_info]))
        except:
            ip_addresses = None
        return ip_addresses

    def set_country(self, country_ip_list):
        if self.ip_addresses:
            for ip in self.ip_addresses:
                self.parsed_ips[ip] = country_ip_list[ip]

    def __str__(self):
        padding = " " * (self.padding - len(self.domain_name) + 1)
        output_message = f"{self.domain_name}"
        if not self.parsed_ips:
            output_message += padding + f"────> {colorize_text('No DNS entry found.', 91)}"
        else:
            output_message += padding + "────> " + \
                f"\n{' ' * (self.padding)} ────> ".join(
                    f"{colorize_text(ip, 92)}{' ' * (15 - len(ip))} [{details[0]}], {colorize_text(details[1], 93)}"
                    for ip, details in self.parsed_ips.items())
        return output_message

class ParentDomain:
    def __init__(self, domain, shodan=False): 
        self.shodan = False
        self.domain_name = domain
        self.subdomains = self.subdomain_search()
        # Let's discover child-domains from crt.sh:
        max_length = len(max(self.subdomains, key=len))
        # Now, let's create SubDomain objects.
        self.subdomains = [SubDomain(subdomain, max_length) for subdomain in self.subdomains]
        self.sort_subdomains()
        # Only unique ips.
        _unique_ips = list(set([ip for ip_block in self.subdomains if ip_block.ip_addresses for ip in ip_block.ip_addresses]))
        # Let's geolocate the IPs.
        country_code_list = self.geolocate_ips(_unique_ips)
        
        for subdomain in self.subdomains:
            subdomain.set_country(country_code_list)
            print(subdomain)

    def geolocate_ips(self, ip_list):
        response = requests.post("http://ip-api.com/batch?fields=status,countryCode,isp,org,query&lang=en", json=ip_list)
        if response.status_code != 200:
            print(f"Error: {response.status_code} :: {response.text}")
            exit(0)
        return_json = json.loads(response.text)
        parsed_ips = {}
        for entry in return_json:
            parsed_ips[entry["query"]] = [entry["countryCode"], (entry["org"])]
        return parsed_ips
            

    def parse_crt(self, response):
        # Regex to fetch every URL on the site.
        regex = r'([A-z0-9]+\.[A-z0-9]+\.[A-z0-9]+)'
        domains = re.findall(regex, response)
        # Only matching domains that match the parent domain.
        filtered_domains = list(set([domain for domain in domains if self.domain_name in domain]))
        return filtered_domains

    def crt_search(self):
        response = requests.get("https://crt.sh/?Identity=" + self.domain_name)
        if response.status_code != 200:
            print(f"Error: {response.status_code} :: {response.text}")
            exit(0)
        return self.parse_crt(response.text)

    def shodan_search(self):
        ""

    def subdomain_search(self):
        # First, a crt.sh search.
        crt_domains = self.crt_search()
        # Then, a shodan search.
        shodan_domains = self.shodan_search() if self.shodan else []
        found_domains = list(set(crt_domains + shodan_domains + [self.domain_name]))
        return found_domains

    def sort_subdomains(self):
        self.subdomains.sort(key=lambda x: x.domain_name)



def colorize_text(text, colour):
    return f"\033[{colour}m{text}\033[0m"


def parse_args(arguments):
        url_regex = r'(https?://)?(www\.)?'
        domains = [re.sub(url_regex, "", argument) for argument in arguments]
        return domains

def main(args):
    domains = parse_args(args)
    ParentDomain(domains[0])

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: subspy [Domains]")
        exit(0)
    main(sys.argv[1:])

