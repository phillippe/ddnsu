#!/usr/bin/env python

import argparse
import datetime
import http.client
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree

_IP_ADDRESS_PATTERN = re.compile(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$")
_CHECK_IP_HOST = "checkip.amazonaws.com"
_DDNS_UPDATE_HOST = "dynamicdns.park-your-domain.com"
_CONFIG_SCHEMA_VERSION = 1
_CONFIG_FILE_NAME = "ddnsu_config.json"
_PREV_IP_SCHEMA_VERSION = 1
_PREV_IP_FILE_NAME = "ddnsu_prev_ip.json"

log = logging.getLogger("ddnsu")


def _parse_args(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("--pswd", help="The DDNS password")
    parser.add_argument("--domain", help="The domain to be updated")
    parser.add_argument("--hosts", nargs="*", help="The hosts to be updated (space-delimited)")
    parser.add_argument("--ip", help="The new IP address or `detect` to query a web service for an address")
    parser.add_argument("-w", "--working_dir", help="The path to use as the working directory", default=os.getcwd())
    parser.add_argument("-l", "--log_level", help="The logging level to use", default="INFO")
    parser.add_argument("-f", "--force", action="store_true", help="Update even if IP address is unchanged")

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
    path = os.path.join(working_dir, _CONFIG_FILE_NAME)
    log.debug("Reading config file: %s", path)

    if not os.path.exists(path):
        log.debug("Config file does not exist")
        config = {}
    elif not os.path.isfile(path):
        log.warning("Invalid config (not a file)")
        config = {}
    else:
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)

                if type(config) is not dict:
                    log.warning("Invalid config file (root element is not an object)")
                    config = {'schema': _CONFIG_SCHEMA_VERSION, 'config': {}}

                schema = config.get('schema')

                if schema is None:
                    log.warning("Invalid config file (no schema version specified)")
                    config = {}
                elif schema != _CONFIG_SCHEMA_VERSION:
                    log.warning("Invalid config file (current schema: %d. found: %s)", _CONFIG_SCHEMA_VERSION, schema)
                    config = {}
                elif 'config' not in config:
                    log.warning("Invalid config file (root object is missing a 'config' child object)")
                    config = {}
                else:
                    config = config['config']
        except OSError:
            log.exception("Failed to read config file")
            config = {}

    return config


def _get_ip(arg):
    if arg is None or _IP_ADDRESS_PATTERN.match(arg):
        ip = arg
    elif arg == "detect":
        log.info("Querying %s for IP address", _CHECK_IP_HOST)

        connection = http.client.HTTPSConnection(_CHECK_IP_HOST)
        connection.request("GET", "/")
        response = connection.getresponse()

        if response.status == 200:
            ip = response.read().decode().strip()
            if not _IP_ADDRESS_PATTERN.match(ip):
                log.warning("Received invalid IP address: %s", ip)
                ip = None
        else:
            log.warning("Failed to acquire IP address. status=%s, reason=%s", response.status, response.reason)
            ip = None

        connection.close()
    else:
        log.warning("Invalid IP address: %s", arg)
        ip = None

    return ip


def _is_prev_ip_same(working_dir, ip):
    if ip is None:
        return False

    path = os.path.join(working_dir, _PREV_IP_FILE_NAME)

    if not os.path.exists(path):
        log.info("No previous IP address recorded")
        return False
    elif os.path.isdir(path):
        log.warning("Failed to read previous IP address (path points to a directory): %s", path)
        return False

    try:
        log.debug("Reading previous IP from file: %s", path)
        with open(path, "r", encoding="utf-8") as f:
            root = json.load(f)

            if type(root) is not dict:
                log.warning("Invalid prev_ip file (root element is not an object)")
                return False

            schema = root.get('schema')

            if schema is None:
                log.warning("Invalid prev_ip file (no schema version specified)")
                return None
            elif schema != _PREV_IP_SCHEMA_VERSION:
                log.warning("Invalid prev_ip file (current schema: %d. found: %s)", _PREV_IP_SCHEMA_VERSION, schema)
                return None
            elif 'prev_ip' not in root:
                log.warning("Invalid prev_ip file (root object is missing a 'prev_ip' entry)")
                return None
            else:
                prev_ip = root['prev_ip']
                log.debug("Previous IP: %s", prev_ip)
                return prev_ip == ip
    except OSError:
        log.exception("Failed to read IP address from file")
        return False


def _update_ip(pswd, domain, hosts, ip):
    if not pswd or not domain or not hosts:
        log.error("`pswd`, `domain`, and `hosts` must not be empty")
        return None

    url = f"/update?domain={domain}&password={pswd}"

    if ip is None:
        log.info("Leaving IP address blank for Namecheap to identify")
    else:
        log.info("Using IP address %s", ip)
        url = f"{url}&ip={ip}"

    log.info("Updating records")
    connection = http.client.HTTPSConnection(_DDNS_UPDATE_HOST)
    updated_ip = None

    for host in hosts:
        if not host:
            continue

        connection.request("GET", f"{url}&host={host}")
        response = connection.getresponse()

        if response.status == 200:
            tree = xml.etree.ElementTree.fromstring(response.read().decode())
            err_count = tree.findtext('ErrCount')
            if err_count == "0":
                updated_ip = tree.findtext('IP')
                log.debug("Successfully updated %s.%s", host, domain)
            elif err_count is not None:
                log.warning("Failed to update %s.%s", host, domain)
        else:
            log.warning("Failed to update host %s.%s; status=%s, reason=%s",
                        host, domain, response.status, response.reason)

    connection.close()
    return updated_ip


def _record_updated_ip(working_dir, ip):
    if ip is None:
        log.debug("IP address is None. Skipping writing to file")
        return

    path = os.path.join(working_dir, _PREV_IP_FILE_NAME)

    if os.path.isdir(path):
        log.warning("Cannot write IP address to file (path points to a directory): %s", path)
        return

    try:
        log.debug("Writing IP address to file: %s", path)
        with open(path, "w", encoding="utf-8") as f:
            contents = {
                'schema': _PREV_IP_SCHEMA_VERSION,
                'prev_ip': ip.strip()
            }
            json.dump(contents, f, indent=4, ensure_ascii=False)
    except (OSError, TypeError):
        log.exception("Failed to write IP address to file")


def run(argv):
    args = _parse_args(argv)
    working_dir = os.path.realpath(args.working_dir)

    _check_working_dir(working_dir)
    _configure_logger(working_dir, args.log_level.upper())

    log.info("Starting ddnsu")

    config = _read_config(working_dir)
    # override config values with argument values
    for name, val in vars(args).items():
        if val is not None:
            config[name] = val

    ip = _get_ip(config.get('ip'))
    if not config['force'] and _is_prev_ip_same(working_dir, ip):
        log.info("Previous IP address is the same as the new IP address. Skipping update")
    else:
        updated_ip = _update_ip(config.get('pswd'), config.get('domain'), config.get('hosts'), ip)
        _record_updated_ip(working_dir, updated_ip)

    log.info("Done")


def main():
    run(sys.argv[1:])
