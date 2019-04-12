#!/usr/bin/python
import argparse
import json
import logging
import os
from ipaddress import ip_address, ip_network
from proteus import RESTClient
from shutil import copyfile
from sys import exit


HOSTNAME = 'proteus.spectrum-health.org'
CREDPATH = os.path.expanduser('~') + '/.proteus'


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
    if mac_entity['id'] != 0:
        linked_ips = session.get_linked_entities(mac_entity['id'])
        linked_ips = [session.entity_to_json(linked_ip) for linked_ip in linked_ips]
        output = {
            'mac': session.entity_to_json(mac_entity),
            'linked_ips': linked_ips
        }
    else:
        output = mac_entity
    return output


def search_name(session, name):
    results = session.search_ip_by_name(name)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    group_me_in = parser.add_mutually_exclusive_group(required=True)
    group_me_in.add_argument('-i', '--ip', help='IP address')
    group_me_in.add_argument('-m', '--mac', help='MAC address')
    group_me_in.add_argument('-n', '--name', help='Device name')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    group_me_out = parser.add_mutually_exclusive_group()
    group_me_out.add_argument('--text', help='text output', action='store_true')
    group_me_out.add_argument('--csv', help='csv output', action='store_true')
    group_me_out.add_argument('--json', help='json output, this is the default', action='store_true')
    args = parser.parse_args()

    # Handle loading of credentials
    if args.creds:
        copyfile(args.creds, CREDPATH)
        logging.info('Copied {} to {}'.format(args.creds, CREDPATH))
    with open(CREDPATH) as f:
        creds = json.load(f)
        username = creds['username']
        password = creds['password']
        logging.info('Loaded credentials from {}'.format(CREDPATH))

    # Enable logging if requested
    # if args.loglevel:
    #     level = getattr(logging, args.loglevel.upper())
    #     logging.basicConfig(level=level)

    # Instantiate Bluecat REST Client
    client = RESTClient(HOSTNAME, username, password, loglevel=args.loglevel)

    if args.ip:
        results = search_ip(client, args.ip)
    elif args.mac:
        results = search_mac(client, args.mac)
    elif args.name:
        results = search_name(client, args.name)

    if args.text:
        for result in results:
            result['properties'] = client.prop_s2d(result['properties'])
            if args.text:
                print('Name       : {}'.format(result['name']))
                print('State      : {}'.format(result['properties']['state']))
                print('IP Address : {}'.format(result['properties']['address']))
                if 'macAddress' in result['properties']:
                    print('MAC Address: {}'.format(result['properties']['macAddress']))
                print('\n\n')
    elif args.csv:
        print('Name,State,IP,MAC')
        for result in results:
            result['properties'] = client.prop_s2d(result['properties'])
            name = result['name']
            state = result['properties']['state']
            ip = result['properties']['address']
            if 'macAddress' in result['properties']:
                mac = result['properties']['macAddress']
            else:
                mac = 'N/A'
            print(','.join([name, state, ip, mac]))
    else:
        print(json.dumps(results, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
