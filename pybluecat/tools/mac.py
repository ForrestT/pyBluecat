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
    ip_entity = session.get_ip_address(ip)
    ip = session.entity_to_json(ip_entity)
    if 'macAddress' in ip['properties']:
        mac_entity = session.get_mac_address(ip['properties']['macAddress'])
        mac = session.entity_to_json(mac_entity)
        output = {
            'ip': ip,
            'mac': mac
        }
    else:
        output = {
            'ip': ip,
            'mac': None
        }
    return output


def search_mac(session, mac):
    formatted_mac = mac.replace('.', '').replace(':', '').replace('-', '')
    mac_entity = session.get_mac_address(formatted_mac)
    linked_ips = session.get_linked_entities(mac_entity['id'])
    linked_ips = [session.entity_to_json(linked_ip) for linked_ip in linked_ips]
    output = {
        'mac': session.entity_to_json(mac_entity),
        'linked_ips': linked_ips
    }
    return output


def search_name(session, name):
    results = session.search_ip_by_name(name)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    parser.add_argument('-m', '--mac', help='MAC address')
    parser.add_argument('-n', '--name', help='Device name')
    parser.add_argument('-p', '--properties', help='Properties')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    args = parser.parse_args()

    # Handle loading of credentials
    creds = pybluecat.get_creds(args.creds)
    hostname = creds['hostname']
    username = creds['username']
    password = creds['password']

    # Enable logging if requested
    # if args.loglevel:
    #     level = getattr(logging, args.loglevel.upper())
    #     logging.basicConfig(level=level)

    # Instantiate Bluecat REST Client
    bam = pybluecat.BAM(hostname, username, password, loglevel=args.loglevel)
    r = bam.create_mac_address(args.mac, args.name, args.properties)
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
