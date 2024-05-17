#!/usr/bin/env python

import argparse
import http.client
import re
import sys
import xml.etree.ElementTree as xml

_IP_ADDRESS_PATTERN = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$")
_CHECK_IP_HOST = "checkip.amazonaws.com"
_DDNS_UPDATE_HOST = "dynamicdns.park-your-domain.com"


def _get_ip():
    connection = http.client.HTTPSConnection(_CHECK_IP_HOST)
    connection.request("GET", "/")
    response = connection.getresponse()

    if response.status != 200:
        print(f"Failed to acquire IP address. status={response.status}, reason={response.reason}")
        ip = None
    else:
        ip = response.read().decode().strip()
        print(f"Acquired IP address from {_CHECK_IP_HOST}")

    connection.close()
    return ip


def _update_ip(pswd, domain, hosts, ip):
    url = f"/update?domain={domain}&password={pswd}"

    if ip is None:
        sys.exit("No IP address")
    elif ip == "namecheap":
        print("Leaving IP address blank for Namecheap to identify")
    else:
        if not _IP_ADDRESS_PATTERN.match(ip):
            sys.exit(f"Invalid IP address: {ip}")
        url = f"{url}&ip={ip}"
        print(f"Using IP address {ip}")

    connection = http.client.HTTPSConnection(_DDNS_UPDATE_HOST)

    for host in hosts:
        connection.request("GET", f"{url}&host={host}")
        response = connection.getresponse()

        if response.status == 200:
            tree = xml.fromstring(response.read().decode())
            err_count = tree.findtext("ErrCount")
            if err_count == "0":
                print(f"Successfully updated {host}.{domain}")
            elif err_count is not None:
                print(f"Failed to update {host}.{domain}")
        else:
            print(f"Failed to update host {host}.{domain}; status={response.status}, reason={response.reason}")

    connection.close()


def main(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("pswd", help="The DDNS password")
    parser.add_argument("domain", help="The domain to be updated")
    parser.add_argument("hosts", help="A comma separated list of hosts to be updated")
    parser.add_argument("--ip", help="The new IP address", default="namecheap")

    args, _ = parser.parse_known_args(argv)
    ip = _get_ip() if args.ip == "detect" else args.ip

    _update_ip(args.pswd, args.domain, args.hosts.split(","), ip)


if __name__ == "__main__":
    main(sys.argv[1:])
