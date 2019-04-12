#!/usr/bin/python
import argparse
import json
import logging
import os
import pybluecat
from ipaddress import ip_address, ip_network
from shutil import copyfile
from sys import exit


def search_ip(session, ip):
    results = session.get_ip_address(ip)
    return [results]


def format_mac(mac):
    return mac.replace('.', '').replace(':', '').replace('-', '').lower()


def search_mac(session, mac):
    formatted_mac = format_mac(mac)
    mac_entity = session.get_mac_address(formatted_mac)
    results = session.get_linked_entities(mac_entity['id'])
    return results


def search_name(session, name):
    results = session.search_ip_by_name(name)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    parser.add_argument('-i', '--ip', help='IP address')
    parser.add_argument('-m', '--mac', help='MAC address')
    parser.add_argument('-n', '--name', help='Device name')
    parser.add_argument('-l', '--loglevel', default='critical', help='enable logging',
                        choices=['critical', 'error', 'warning', 'info', 'debug'])
    match_group = parser.add_mutually_exclusive_group()
    match_group.add_argument('--match_all', action='store_true')
    match_group.add_argument('--match_any', action='store_true')
    args = parser.parse_args()

    # Setup console logging
    logger = logging.getLogger(__name__)
    loglevel = getattr(logging, args.loglevel.upper())
    logger.setLevel(level=loglevel)
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)
    logger.propagate = False

    # Handle loading of credentials
    creds = pybluecat.get_creds(args.creds)
    hostname = creds['hostname']
    username = creds['username']
    password = creds['password']

    # Instantiate Bluecat REST Client
    bam = pybluecat.BAM(hostname, username, password)  # , loglevel=args.loglevel)

    # Normalizing Arguments due to Rundeck requirements
    if args.ip == '':
        ip = None
    else:
        ip = args.ip
    if args.mac == '':
        mac = None
    else:
        mac = args.mac
    if args.name == '':
        name = None
    else:
        name = args.name

    # Use provided fields to search Bluecat Objects 
    results = []
    if ip is not None:
        results += search_ip(bam, ip)
    if mac is not None:
        results += search_mac(bam, mac)
    if name is not None:
        results += search_name(bam, name)

    # Eliminate Dupes and conflicting filters
    matches = []
    for result in results:
        ip_obj = bam.entity_to_json(result)
        # Skip NULL objects
        if ip_obj['properties'] is None:
            continue
        # Skip Duplicates
        if ip_obj in matches:
            continue
        # Gather details about the ip_object
        res_name = ip_obj['name']
        res_ip = ip_obj['properties']['address']
        if 'macAddress' in ip_obj['properties']:
            res_mac = ip_obj['properties']['macAddress']
        else:
            res_mac = ''
        logger.info('NAME: {}, IP: {}, MAC: {}'.format(res_name, res_ip, res_mac))
        # If IP Object state is not "DHCP_RESERVED" DO NOT DELETE
        if ip_obj['properties']['state'] != 'DHCP_RESERVED':
            logger.info('IP Object is NOT a DHCP Reservation, ignoring objects with state: {}'.format(ip_obj['properties']['state']))
            continue
        # If --match_all is set, ensure ALL set fields match the reservation
        if args.match_all:
            # If --hostname is set and doesn't match, skip to next reservation
            if name is not None and res_name.lower() != name.lower():
                logger.info('Reservation doesn\'t match --hostname filter with --match_all set, ignoring')
                continue
            # If --ip_addr is set and doesn't match, skip to next reservation
            if ip is not None and res_ip != str(ip):
                logger.info('Reservation doesn\'t match --ip_addr filter with --match_all set, ignoring')
                continue
            # If --mac_addr is set and doesn't match, skip to next reservation
            if mac is not None and format_mac(res_mac) != mac:
                logger.info('Reservation doesn\'t match --mac_addr filter with --match_all set, ignoring')
                continue
        matches.append(ip_obj)

    # Output the remaining matched ip objects
    print(json.dumps(matches, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

