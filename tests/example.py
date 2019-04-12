#!/usr/bin/python
from proteus import RESTClient
import argparse
import json


parser = argparse.ArgumentParser()
parser.add_argument('cidr', help='CIDR(s) to act as root for enumeration')
parser.add_argument('-a', '--append', help='omit header for appending to previous output', action='store_true')
parser.add_argument('-c', '--creds', help='path to file containing credentials')
parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                    default='critical', help='enable logging')
args = parser.parse_args()


credpath = args.creds if args.creds is not None else '/home/fmt/creds/network.json'
with open(credpath) as f:
    creds = json.load(f)

cidr = args.cidr

c = RESTClient('proteus', creds['username'], creds['password'], loglevel=args.loglevel)
# config = c.get_entity_by_name(0, 'Spectrum Health', 'Configuration')
startBlock = c.get_block_by_cidr(c.config['id'], cidr)
if startBlock['id'] == 0:
    startBlock = c.get_network_by_cidr(c.config['id'], cidr)
print(json.dumps(startBlock, indent=2, sort_keys=True))
