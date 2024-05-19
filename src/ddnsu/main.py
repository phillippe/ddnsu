#!/usr/bin/env python

import argparse
import datetime
import http.client
import logging
import os
import re
import sys
import xml.etree.ElementTree as xml

_IP_ADDRESS_PATTERN = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$")
_CHECK_IP_HOST = "checkip.amazonaws.com"
_DDNS_UPDATE_HOST = "dynamicdns.park-your-domain.com"

log = logging.getLogger("ddnsu")


def _check_working_dir(working_dir):
    # Logger isn't configured at this point so use print instead
    if not os.path.exists(working_dir):
        os.makedirs(working_dir, exist_ok=True)
    elif os.path.isfile(working_dir):
        print(f"Invalid directory path (points to a file): {working_dir}")
        sys.exit(1)
    elif not os.access(working_dir, os.R_OK | os.W_OK):
        print(f"Directory is not readable/writable: {working_dir}")
        sys.exit(1)


def _configure_logger(working_dir, level):
    path = os.path.join(working_dir, "logs")
    os.makedirs(path, exist_ok=True)

    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%H:%M:%S")
    handler = logging.FileHandler(os.path.join(path, f"ddnsu_{datetime.date.today()}.log"), encoding="utf-8")
    handler.setFormatter(formatter)
    log.addHandler(handler)

    formatter = logging.Formatter("%(asctime)s: %(message)s", "%H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    log.addHandler(handler)

    levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
    }

    if level in levels:
        log.setLevel(levels[level])
    else:
        log.setLevel(logging.INFO)
        log.warning("Invalid logging level: %s. Logging level set to INFO", level)


def _get_ip():
    log.info("Querying %s for IP address", _CHECK_IP_HOST)

    connection = http.client.HTTPSConnection(_CHECK_IP_HOST)
    connection.request("GET", "/")
    response = connection.getresponse()

    if response.status != 200:
        log.warning("Failed to acquire IP address. status=%s, reason=%s", response.status, response.reason)
        ip = None
    else:
        ip = response.read().decode().strip()

    connection.close()
    return ip


def _update_ip(pswd, domain, hosts, ip):
    url = f"/update?domain={domain}&password={pswd}"

    if ip is None:
        log.error("No IP address")
        return
    elif ip == "namecheap":
        log.info("Leaving IP address blank for Namecheap to identify")
    elif _IP_ADDRESS_PATTERN.match(ip):
        log.info("Using IP address %s", ip)
        url = f"{url}&ip={ip}"
    else:
        log.error("Invalid IP address: %s", ip)
        return

    log.info("Updating records")
    connection = http.client.HTTPSConnection(_DDNS_UPDATE_HOST)

    for host in hosts:
        connection.request("GET", f"{url}&host={host}")
        response = connection.getresponse()

        if response.status == 200:
            tree = xml.fromstring(response.read().decode())
            err_count = tree.findtext("ErrCount")
            if err_count == "0":
                log.debug("Successfully updated %s.%s", host, domain)
            elif err_count is not None:
                log.warning("Failed to update %s.%s", host, domain)
        else:
            log.warning("Failed to update host %s.%s; status=%s, reason=%s",
                        host, domain, response.status, response.reason)

    connection.close()


def main(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("pswd", help="The DDNS password")
    parser.add_argument("domain", help="The domain to be updated")
    parser.add_argument("hosts", help="A comma separated list of hosts to be updated")
    parser.add_argument("--ip", help="The new IP address", default="namecheap")
    parser.add_argument("-w", "--working_dir", help="The path to use as the working directory", default=os.getcwd())
    parser.add_argument("-l", "--log_level", help="The logging level to use", default="INFO")

    args, _ = parser.parse_known_args(argv)

    _check_working_dir(args.working_dir)
    _configure_logger(args.working_dir, args.log_level.upper())

    log.info("Starting ddnsu")

    ip = _get_ip() if args.ip == "detect" else args.ip
    _update_ip(args.pswd, args.domain, args.hosts.split(","), ip)

    log.info("Done")


if __name__ == "__main__":
    main(sys.argv[1:])
