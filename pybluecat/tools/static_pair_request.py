#!/usr/bin/python
import argparse
import json
import logging
import pybluecat
from ipaddress import ip_address, ip_network
from sys import exit


def ping(host):
    import subprocess
    try:
        r = subprocess.check_output(['ping', '-c', '1', host], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def dns_A_exists(host):
    try:
        a = resolver.query(host + '.spectrum-health.org', 'A')
        return a
    except:
        return None

def dns_PTR_exists(host):
    try:
        ptr = reversename.from_address(host)
        name = resolver.query(ptr, 'PTR')[0]
        return str(name)
    except:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname', help='hostname')
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    group_ME = parser.add_mutually_exclusive_group(required=True)
    group_ME.add_argument('-n', '--network', nargs=2, help='network address within desired subnet')
    group_ME.add_argument('-e', '--environment', help='environment from which to choose a network')
    parser.add_argument('-l', '--loglevel', choices=['warning', 'info', 'debug'], help='enable debugging')
    args = parser.parse_args()

    NETWORK_ENVS = {
        'lab': [u'10.168.131.0/24', u'10.168.161.0/24'],
        'dmz-vip': [u'167.73.15.0/24', u'167.73.31.0/24']
        }

    if args.loglevel:
        level = getattr(logging, args.loglevel.upper())
        logging.basicConfig(level=level)

    hostname = args.hostname.lower()
    creds = pybluecat.get_creds(args.creds)
    bam = pybluecat.BAM(creds['hostname'], creds['username'], creds['password'])

    # Get Networks List
    if args.network:
        net1 = args.network[0]
        net2 = args.network[1]
    elif args.environment:
        net1, net2 = NETWORK_ENVS[args.environment]

    # Reserve the pairs
    addresses = bam.assign_ip_address_pair(net1, net2, args.hostname)
    print(json.dumps(addresses, indent=2))


if __name__ == '__main__':
    main()

