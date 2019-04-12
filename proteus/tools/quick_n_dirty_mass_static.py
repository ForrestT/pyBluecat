#!/usr/bin/python
import argparse
import json
import logging
import proteus
from ipaddress import ip_address, ip_network
from sys import exit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file_path')
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    parser.add_argument('-l', '--loglevel', choices=['warning', 'info', 'debug'], help='enable debugging')
    args = parser.parse_args()

    if args.loglevel:
        level = getattr(logging, args.loglevel.upper())
        logging.basicConfig(level=level)

    with open(args.file_path) as f:
        reservations = [line.strip().split(',') for line in f.readlines() if line.strip() != '']

    creds = proteus.get_creds(args.creds)
    with proteus.RESTClient(**creds) as bam:
    for reservation in reservations:
        hostname = reservation[0]
        network = 
        logging.info('Working through network: {}'.format(str(network)))
        # Get Network Object and set dhcp_offset based on CIDR
        netObj = c.get_network(str(network.network_address))
        netObj = c.entity_to_json(netObj)
        if network.prefixlen > 24:
            dhcp_offset = 0
        else:
            dhcp_offset = 30
        logging.info('DHCP-Offsest: {}'.format(str(dhcp_offset)))
        # Ensure IPs in the offset are 'reserved'
        while not foundIP:
            logging.info('Checking Status of Offset Addreses')
            ip = c.get_next_ip_address(netObj['id'])
            logging.info('Address {}'.format(str(ip)))
            if ip is None or ip == '':
                break
            elif network.network_address + dhcp_offset >= ip_address(unicode(ip)):
                c.assign_ip_address('', ip, '', 'MAKE_RESERVED', '')
                logging.info('Setting IP Address as RESERVED: {}'.format(ip))
            else:
                break
        # If an existing IP has not been found yet, start working through
        # every free IP in the Proteus Network until one is assigned or net is
        # exhausted
        if not foundIP:
            logging.info('Determining next available IP Address')
            while True:
                ipObj = c.assign_next_ip_address(netObj['id'], hostname)
                # None as a result indicates network has no next IP, end loop
                if ipObj['id'] == 0:
                    break
                ipObj = c.entity_to_json(ipObj)
                logging.info('IP Address free in Proteus: {}'.format(ipObj['properties']['address']))
                # Check if IP has existing PTR record, if True, write it to Proteus, try next IP
                ptr = dns_PTR_exists(ipObj['properties']['address'])
                if ptr:
                    logging.info('PTR Record found for Address: {}'.format(ptr))
                    ipObj['name'] = ptr.split('.')[0]
                    ipObj = c.json_to_entity(ipObj)
                    c.update(ipObj)
                # Try to Ping the IP address, if response, log in Proteus, try next IP
                elif ping(ipObj['properties']['address']):
                    logging.info('Address responded to ping')
                    ipObj['name'] = 'IN-USE: something pinged'
                    ipObj = c.json_to_entity(ipObj)
                    c.update(ipObj)
                # Finally, reserve the IP in Proteus for the hostname
                else:
                    logging.info('Address doesn\'t ping or have PTR record')
                    foundIP = True
                    break
        # If an IP has been found, either new or existing, return results and exit
        if foundIP:
            network = ip_network(unicode(netObj['properties']['CIDR']))
            output = {
                'ip_addr': ipObj['properties']['address'],
                'gateway': str(network.network_address + 1),
                'net_mask': str(network.netmask),
                'net_name': netObj['name'],
                '_ipobj': ipObj,
                '_netobj': netObj
            }
            print(json.dumps(output, sort_keys=True, indent=4))
            c.logout()
            exit()
    if not foundIP:
        print('No Addresses Available.')
        exit(1)


if __name__ == '__main__':
    main()

