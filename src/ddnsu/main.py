#!/usr/bin/env python

import argparse
import datetime
import http.client
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as xml

_IP_ADDRESS_PATTERN = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$")
_CHECK_IP_HOST = "checkip.amazonaws.com"
_DDNS_UPDATE_HOST = "dynamicdns.park-your-domain.com"
_CONFIG_SCHEMA_VERSION = 1

log = logging.getLogger("ddnsu")


def _parse_args(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("--pswd", help="The DDNS password")
    parser.add_argument("--domain", help="The domain to be updated")
    parser.add_argument("--hosts", action="append", help="A host to be updated (can be repeated to specify multiple)")
    parser.add_argument("--ip", help="The new IP address", default="namecheap")
    parser.add_argument("-w", "--working_dir", help="The path to use as the working directory", default=os.getcwd())
    parser.add_argument("-l", "--log_level", help="The logging level to use", default="INFO")

    return parser.parse_known_args(argv)[0]


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


def _read_config(working_dir):
    path = os.path.join(working_dir, "ddnsu_config.json")
    log.debug("Reading config file: %s", path)

    if not os.path.exists(path):
        log.debug("Config file does not exist")
        config = {}
    elif not os.path.isfile(path):
        log.warning("Invalid config (Not a file)")
        config = {}
    else:
        try:
            with open("ddnsu_config.json", "r") as f:
                config = json.load(f)

                if type(config) is not dict:
                    log.warning("Invalid config file (Root element is not an object)")
                    config = {'schema': _CONFIG_SCHEMA_VERSION, 'config': {}}

                schema = config.get('schema')

                if schema is None:
                    log.warning("Invalid config file (No schema version specified)")
                    config = {}
                elif schema != _CONFIG_SCHEMA_VERSION:
                    log.warning("Invalid config file (Current schema: %d. Found: %s)", _CONFIG_SCHEMA_VERSION, schema)
                    config = {}
                elif 'config' not in config:
                    log.warning("Invalid config file (Root object is missing a 'config' child object)")
                    config = {}
                else:
                    config = config['config']
        except OSError:
            log.exception("Failed to read config file")
            config = {}

    return config


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
    if not pswd or not domain or not hosts:
        log.error("`pswd`, `domain`, and `hosts` must not be empty")
        return

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
        if not host:
            continue

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


def run(argv):
    args = _parse_args(argv)
    _check_working_dir(args.working_dir)
    _configure_logger(args.working_dir, args.log_level.upper())
    config = _read_config(args.working_dir)

    # override config values with argument values
    for name, val in vars(args).items():
        if val is not None:
            config[name] = val

    log.info("Starting ddnsu")

    ip = _get_ip() if config.get('ip') == "detect" else config.get('ip')
    _update_ip(config.get('pswd'), config.get('domain'), config.get('hosts'), ip)

    log.info("Done")


def main():
    run(sys.argv[1:])
