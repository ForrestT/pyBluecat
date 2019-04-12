#!/usr/bin/python
"""Walk BAM and output all subnets and associated info
"""
from ipaddress import ip_address, ip_network
import argparse
import json
import pybluecat
import re
import sys


CIDR_REGEX = re.compile(r'(?<=CIDR=)[^|]+')


def block_in_blacklist(block):
    try:
        cidr = CIDR_REGEX.findall(block['properties'])[0]
    except Exception:
        print(json.dumps(block, indent=2))
        sys.exit('Couldn\'t find CIDR in Block Properties')
    return cidr in CIDR_BLACKLIST


def name_in_list(entity, kw_list):
    if entity['name'] is None:
        entity['name'] = ''
    return any(keyword in entity['name'].lower() for keyword in kw_list)


def get_line(session, netObj):
    properties = session.prop_s2d(netObj['properties'])
    cidr = properties['CIDR'] if 'CIDR' in properties else ''
    vlan = properties['Vlan'] if 'Vlan' in properties else ''
    loc = properties['Location'] if 'Location' in properties else ''
    return '{c},"{n}",{t},{v},"{l}"'.format(c=cidr, n=netObj['name'], t=netObj['type'], v=vlan, l=loc)


def walk_networks(session, start):
    # Get all Blocks and Subnets within the Start Block
    blocks = session.get_entities(start['id'], 'IP4Block', 0, 256)
    subnets = session.get_entities(start['id'], 'IP4Network', 0, 256)
    # If there are Blocks within Start, evaluate them
    if len(blocks) > 0:
        for block in blocks:
            # Do any filters preclude this block from use?
            if (block_in_blacklist(block)
                or name_in_list(block, KW_BLACKLIST)
                or not name_in_list(block, KW_WHITELIST)):
                # Skip block
                continue
            # Print the Block info if Global flag not set
            if not IGNORE_BLOCKS:
                print(get_line(session, block))
            # RECURSE!!!
            walk_networks(session, block)
    # If there are Subnets within Start, evaluate them
    for subnet in subnets:
        # Do any filters preclude this subnet from use?
        if (name_in_list(subnet, KW_BLACKLIST)
            or not name_in_list(subnet, KW_WHITELIST)):
            # Skip subnet
            continue
        # searches properties string for the CIDR, then creates net obj
        net = ip_network(unicode(CIDR_REGEX.findall(subnet['properties'])[0]))
        # print the network if it meets size requirements
        if (net.prefixlen <= MINIMUM
            and net.prefixlen >= MAXIMUM):
            print(get_line(session, subnet))


def find_start_block(session, cidr, start_id):
    cidr = ip_network(unicode(cidr))
    top_blocks = session.get_entities(start_id, 'IP4Block', 0, 1000)
    for block in top_blocks:
        block_cidr = pybluecat.prop_s2d(block['properties'])['CIDR']
        block_net = ip_network(block_cidr)
        if block_net.overlaps(cidr):
            if block_net == cidr:
                return block
            else:
                return(find_start_block(session, cidr, block['id']))


def main():
    # Get and Parse all CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('cidr', nargs='+', help='CIDR(s) to act as root for enumeration')
    parser.add_argument('-a', '--append', help='omit header for appending to previous output', action='store_true')
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    parser.add_argument('--minimum', type=int, default=32, help='Minimum size (inclusive) of subnets, e.g. "24"')
    parser.add_argument('--maximum', type=int, default=0, help='Maximum size (inclusive) of subnets, e.g. "24"')
    parser.add_argument('--ignore_blocks', action='store_true', help='omits IP4Blocks from output')
    parser.add_argument('--cidr_blacklist', help='filepath to list of network blocks to not enumerate')
    kw_group = parser.add_mutually_exclusive_group()
    kw_group.add_argument('--keyword_blacklist', help='filepath to list of name keywords to not enumerate')
    kw_group.add_argument('--keyword_whitelist', help='filepath to list of name keywords to not enumerate')
    args = parser.parse_args()

    # Initialize the Global Ignore Blocks flag
    global IGNORE_BLOCKS
    IGNORE_BLOCKS = args.ignore_blocks
    # Initialize the Global CIDR Minimum size
    global MINIMUM
    MINIMUM = args.minimum
    # Initialize the Global CIDR Maximum size
    global MAXIMUM
    MAXIMUM = args.maximum
    # Initialize the Global CIDR Blacklist
    global CIDR_BLACKLIST
    if args.cidr_blacklist is not None:
        try:
            with open(args.cidr_blacklist) as f:
                CIDR_BLACKLIST = [line.strip().split()[0] for line in f.readlines() if line.strip() != '']
        except Exception:
            sys.exit('blacklist {} could not be parsed'.format(args.cidr_blacklist))
    else:
        CIDR_BLACKLIST = []
    # Initialize the Global Keyword Blacklist
    global KW_BLACKLIST
    if args.keyword_blacklist is not None:
        try:
            with open(args.keyword_blacklist) as f:
                KW_BLACKLIST = [line.strip().split()[0].lower() for line in f.readlines() if line.strip() != '']
        except Exception:
            sys.exit('blacklist {} could not be parsed'.format(args.keyword_blacklist))
    else:
        KW_BLACKLIST = []
    # Initialize the Global Keyword Whitelist
    global KW_WHITELIST
    if args.keyword_whitelist is not None:
        try:
            with open(args.keyword_whitelist) as f:
                KW_WHITELIST = [line.strip().split()[0].lower() for line in f.readlines() if line.strip() != '']
        except Exception:
            sys.exit('whitelist {} could not be parsed'.format(args.keyword_blacklist))
    else:
        KW_WHITELIST = ['']

    # Get Credentials
    creds = pybluecat.get_creds(args.creds)
    # Create the Bluecat sessions
    with pybluecat.BAM(creds['hostname'], creds['username'], creds['password']) as c:
        config = c.get_entity_by_name(0, 'Spectrum Health', 'Configuration')
        # Output headers if append flag not set
        if not args.append:
            print('Network,Name,Type,VLAN,Location')
        # Walk Bluecat from each starting block
        for cidr in args.cidr:
            startBlock = find_start_block(c, cidr, config['id'])
            if not IGNORE_BLOCKS:
                print(get_line(c, startBlock))
            walk_networks(c, startBlock)


if __name__ == '__main__':
    main()
