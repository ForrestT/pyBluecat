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
    group_ME.add_argument('-n', '--network', help='network address within desired subnet')
    group_ME.add_argument('-e', '--environment', help='environment from which to choose a network')
    parser.add_argument('-l', '--loglevel', choices=['warning', 'info', 'debug'], help='enable debugging')
    args = parser.parse_args()

    NETWORK_ENVS = {
        'lab': [ip_network(u'10.168.131.0/24'), ip_network(u'10.168.161.0/24')],
        'dev': [ip_network(u'10.57.128.0/23')],
        'test': [ip_network(u'10.57.144.0/23')],
        'stage': [ip_network(u'10.57.160.0/23')],
        'prod-ctis': [ip_network(u'10.7.96.0/23'), ip_network(u'10.7.98.0/23')],
        'prod-brad': [ip_network(u'10.107.96.0/23'), ip_network(u'10.107.98.0/23')],
        'prod-both': [ip_network(u'10.200.112.0/24'), ip_network(u'10.200.113.0/24')],
        'fmt': [ip_network(u'10.57.136.0/30'), ip_network(u'10.57.136.4/30')]
        }

    if args.loglevel:
        level = getattr(logging, args.loglevel.upper())
        logging.basicConfig(level=level)

    hostname = args.hostname.lower()
    creds = pybluecat.get_creds(args.creds)
    c = pybluecat.BAM(creds['hostname'], creds['username'], creds['password'])

    # Get Networks List
    if args.network:
        netAddr = args.network.split('/')[0]
        netObj = c.get_network(netAddr)
        netObj = c.entity_to_json(netObj)
        networks = [ip_network(netObj['properties']['CIDR'])]
    elif args.environment:
        import requests
        base_url = 'http://infradevapi.spectrum-health.org/infrastructure/'
        env = args.environment.lower()
        url = base_url + env
        proxy = {'http': None, 'https': None}
        if 'dmz' in args.environment:
            dhcp_offset = 0
        try:
            r = requests.get(url, proxies=proxy)
            logging.info(r.request.url)
            logging.info(r.status_code)
            logging.info(r.content)
        except:
            print('Environment Not Found. No Network Available.')
            exit()
        networks = [
            ip_network(net['netaddr'] + '/' + net['netmask'], strict=False)
            for net in json.loads(r.text)[env]
        ]
    logging.info('Networks: {}'.format(str(networks)))


    foundIP = False
    # Check for existing IP reservations in target networks
    results = c.search_by_object_types(hostname, 'IP4Address', 0, 1000)
    logging.info(str(results))
    for result in results:
        temp = c.entity_to_json(result)
        for net in networks:
            if ip_address(temp['properties']['address']) in net:
                foundIP = True
                ipObj = temp
                networks = [net]
                logging.info('Found IP already in existence: {}'.format(json.dumps(ipObj, indent=2)))
                break
    for network in networks:
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
        # every free IP in the BAM Network until one is assigned or net is
        # exhausted
        if not foundIP:
            logging.info('Determining next available IP Address')
            while True:
                ipObj = c.assign_next_ip_address(netObj['id'], hostname)
                # None as a result indicates network has no next IP, end loop
                if ipObj['id'] == 0:
                    break
                ipObj = c.entity_to_json(ipObj)
                logging.info('IP Address free in BAM: {}'.format(ipObj['properties']['address']))
                # Check if IP has existing PTR record, if True, write it to BAM, try next IP
                ptr = dns_PTR_exists(ipObj['properties']['address'])
                if ptr:
                    logging.info('PTR Record found for Address: {}'.format(ptr))
                    ipObj['name'] = ptr.split('.')[0]
                    ipObj = c.json_to_entity(ipObj)
                    c.update(ipObj)
                # Try to Ping the IP address, if response, log in BAM, try next IP
                elif ping(ipObj['properties']['address']):
                    logging.info('Address responded to ping')
                    ipObj['name'] = 'IN-USE: something pinged'
                    ipObj = c.json_to_entity(ipObj)
                    c.update(ipObj)
                # Finally, reserve the IP in BAM for the hostname
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

