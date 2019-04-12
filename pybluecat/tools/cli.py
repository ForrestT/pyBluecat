#!/usr/bin/python
'''Intended to be the one CLI bluecat tool to rule them all
'''
import axapi
import argparse
import json
import logging
import os
import requests
from ipaddress import ip_address, ip_network
from pybluecat import BAM
from pybluecat import data as DATA
from pybluecat.exceptions import BluecatError
from time import sleep


def get_creds(args):
    """Load credentials from file if given
    pull in from environment variables otherwise"""
    if args.creds is not None:
        # Load creds from file
        with open(args.creds) as f:
            creds = json.load(f)
    else:
        # Load creds from Environment variables
        default_filepath = os.environ['HOME'] + '/.bluecat'
        with open(default_filepath) as f:
            creds = json.load(f)
    return creds


def get_client(loglevel):
    """Instantiate bluecat client"""
    hostname = creds['bluecat']['hostname']
    username = creds['bluecat']['username']
    password = creds['bluecat']['password']
    bluecat = BAM(hostname, username, password, loglevel=loglevel)
    return bluecat


def format_mac(mac):
    """Returns a MAC address sans delimiters"""
    return mac.replace('.', '').replace(':', '').replace('-', '')


def process_dhcp_csv(filepath):
    """Converts a DHCP CSV file into a list of dicts"""
    with open(filepath) as f:
        csv = [line.strip().split(',') for line in f.readlines()]
    if any(field in csv[0] for field in ['hostname', 'mac', 'macaddress', 'network']):
        csv.pop(0)
    if '' in csv[-1]:
        csv.pop(-1)
    device_list = [{
            'name': device[0],
            'mac': device[1],
            'net': device[2].split('/')[0]
        }
        for device in csv
    ]
    return device_list


def find_mac_in_net(mac, network):
    """Checks for a MAC address within a network
    return the reservation object if found, None otherwise"""
    mac = format_mac(mac)
    entity = bluecat.get_mac_address(mac)
    try:
        results = bluecat.get_linked_entities(entity['id'])
    except BluecatError:
        return None
    # if 'Object was not found' not in results:
    for result in results:
        ip = bluecat.entity_to_json(result)
        if ip_address(ip['properties']['address']) in network:
            return ip
    return None

def find_name_in_net(name, network):
    """Checks for a reservation with for the given name in the  given
    network. Returns the object if found, otherwise: None"""
    search_results = bluecat.search_ip_by_name(name)
    for result in search_results:
        ip = bluecat.entity_to_json(result)
        if ip_address(ip['properties']['address']) in network:
            if name == ip['name']:
                return ip
    return None


def calculate_offset(network):
    if network.prefixlen > 24:
        offset = None
    else:
        offset = str(network.network_address + 31)
    return offset


def create_static(args):
    pass


def delete_static(args):
    pass


def update_static(args):
    pass


def create_static_bulk(device_list):
    pass


def delete_static_bulk(device_list):
    pass


def update_static_bulk(device_list):
    pass


def create_dhcp(args):
    # determine which networks to use
    if args.network:
        networks = [ip_network(unicode(args.network))]
    else:
        networks = lookup_enviornment_or_some_shit(args.environment)
    # loop through networks until reservation is made
    output = {}
    server_set = set()
    for network in networks:
        # Get Network info from Bluecat
        net_obj = bluecat.get_network(str(network.network_address))
        net_obj = bluecat.entity_to_json(net_obj)
        net = ip_network(net_obj['properties']['CIDR'])
        # Check for existing reservations
        reservation = find_mac_in_net(args.mac, net)
        if reservation is not None:
            output = reservation
            break
        # Set offset for network
        offset = calculate_offset(net)
        # Assign Next Available IP
        mac = format_mac(args.mac)
        response = bluecat.assign_next_ip_address(net_obj['id'], args.hostname, macAddr=mac, action='MAKE_DHCP_RESERVED', offset=offset)
        if bluecat.history[-1].status_code == 200:
            server_set = queue_servers(server_set, net_obj['id'])
            output = bluecat.entity_to_json(response)
            dns_response = create_dns_a_record(args.hostname, output['properties']['address'])
            output['dns-status'] = dns_response.json()['permalink']
            break
    deploy_dhcp_and_monitor(server_set)
    return output


def delete_dhcp(args):
    server_set = set()
    mac_entity = bluecat.get_mac_address(args.mac)
    linked_entities = bluecat.get_linked_entities(mac_entity['id'])
    for ip in linked_entities:
        ip = bluecat.entity_to_json(ip)
        net = bluecat.get_network(ip['properties']['address'])
        response = queue_servers(server_set, net['id'])



def update_dhcp(args):
    pass


def handle_dhcp_bulk(args):
    """Single function to dole out bulk dhcp actions"""
    device_list = process_dhcp_csv(args.filepath)
    if args.delete:
        output = delete_dhcp_bulk(device_list)
    elif args.update:
        output = update_dhcp_bulk(device_list)
    else:
        output = create_dhcp_bulk(device_list)
    return output


def create_dhcp_bulk(device_list):
    output = []
    server_set = set()
    for device in device_list:
        # Get Network info from Bluecat
        net_obj = bluecat.get_network(device['net'])
        net_obj = bluecat.entity_to_json(net_obj)
        net = ip_network(net_obj['properties']['CIDR'])
        # Set offset for network
        offset = calculate_offset(net)
        # Check for existing reservations
        reservation = find_mac_in_net(device['mac'], net)
        if reservation is not None:
            output.append(reservation)
            continue
        else:
            mac = format_mac(device['mac'])
            response = bluecat.assign_next_ip_address(net_obj['id'], device['name'], device['mac'], action='MAKE_DHCP_RESERVED', offset=offset)
            server_set = queue_servers(server_set, net_obj['id'])
            output.append(bluecat.entity_to_json(response))
            # ip_obj = bluecat.entity_to_json(response)
            dns_response = create_dns_a_record(device['name'], response['properties']['address'])
            output[-1]['dns-status'] = dns_response.json()['permalink']
    deploy_dhcp_and_monitor(server_set)
    return output


def delete_dhcp_bulk(device_list):
    pass


def update_dhcp_bulk(device_list):
    output = []
    server_set = set()
    for device in device_list:
        output_entry = {'deleted':[], 'created':[]}
        # Get Network info from Bluecat
        net_obj = bluecat.get_network(device['net'])
        net_obj = bluecat.entity_to_json(net_obj)
        net = ip_network(net_obj['properties']['CIDR'])
        # Find other instances of device of same name
        search_results = bluecat.search_ip_by_name(device['name'])
        for result in search_results:
            # Ensure we only delete exact matches, excluding case
            if result['name'].lower() == device['name'].lower():
                reservation = bluecat.entity_to_json(result)
                # del_addr = ip_address(reservation['properties']['address'])
                del_net = bluecat.get_network(reservation['properties']['address'])
                # delete the reservation from Bluecat
                bluecat.delete(reservation['id'])
                # delete the dns record
                dns_response = delete_dns_a_record(reservation['name'].lower())
                # ensure the changes will get deployed to the correct servers
                server_set = queue_servers(server_set, del_net['id'])
                # log the deletion
                reservation['dns-status'] = dns_response.json()['permalink']
                output_entry['deleted'].append(reservation)
        # Set offset for network
        offset = calculate_offset(net)
        # Check for existing reservations
        reservation = find_mac_in_net(device['mac'], net)
        if reservation is not None:
            output_entry['created'].append(reservation)
            continue
        else:
            mac = format_mac(device['mac'])
            response = bluecat.assign_next_ip_address(net_obj['id'], device['name'], device['mac'], action='MAKE_DHCP_RESERVED', offset=offset)
            server_set = queue_servers(server_set, net_obj['id'])
            output_entry['created'].append(bluecat.entity_to_json(response))
            # ip_obj = bluecat.entity_to_json(response)
            dns_response = create_dns_a_record(device['name'], response['properties']['address'])
            output_entry['created'][-1]['dns-status'] = dns_response.json()['permalink']
        output.append(output_entry)
    deploy_dhcp_and_monitor(server_set)
    return output


def queue_servers(server_set, network_id):
    roles = bluecat.get_deployment_roles(network_id)
    server_primary = bluecat.get_server_for_role(roles[0]['id'])
    server_backup_id = DATA.ADONIS_PAIRS[server_primary['id']]
    server_set.add(server_primary['id'])
    server_set.add(server_backup_id)
    return server_set


def deploy_dhcp_and_monitor(server_set):
    for server in server_set:
        bluecat.deploy_server_services(server, 'DHCP')
    monitor_server_deployment(server_set)


def monitor_server_deployment(server_set):
    for server in server_set:
        status = bluecat.get_deployment_status(server)
        logger.info('{} - {}'.format(DATA.ADONIS_ID_MAP[server], DATA.DEPLOYMENT_STATUS[status]))
    while len(server_set) > 0:
        sleep(2)
        servers = list(server_set)
        for server in servers:
            status = bluecat.get_deployment_status(server)
            if status not in [-1, 0, 1]:
                logger.info('{} - {}'.format(DATA.ADONIS_ID_MAP[server], DATA.DEPLOYMENT_STATUS[status]))
                server_set.remove(server)


def create_dns_a_record(name, ip):
    job_id = creds['rundeck']['jobs']['dns-a']
    url = 'https://rundeck.spectrum-health.org:4443/api/21/job/{}/run'.format(job_id)
    apikey = creds['rundeck']['apikey']
    params = {
        'format': 'json',
        'authtoken': apikey
    }
    body = {
        'argString': '-IPAddress {} -RecordToAdd {}'.format(ip, name)
    }
    response = requests.post(url, json=body, params=params)
    sleep(1)
    return response


def delete_dns_a_record(name):
    job_id = creds['rundeck']['jobs']['dns-a-remove']
    url = 'https://rundeck.spectrum-health.org:4443/api/21/job/{}/run'.format(job_id)
    apikey = creds['rundeck']['apikey']
    params = {
        'format': 'json',
        'authtoken': apikey
    }
    body = {
        'argString': '-RecordToDelete {}'.format(name)
    }
    response = requests.post(url, json=body, params=params)
    sleep(1)
    return response


def add_single_operation_args(parser):
    parser.add_argument('hostname')
    me_group = parser.add_mutually_exclusive_group(required=True)
    me_group.add_argument('-n', '--network', help='network address within desired subnet')
    me_group.add_argument('-e', '--environment', help='environment to assign IP from')
    parser.add_argument('-c', '--creds', help='filepath to read in json credentials')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    parser.add_argument('--nowait', action='store_true', help='do NOT wait for deploy before printing results')


def add_dhcp_single_operation_args(parser):
    add_single_operation_args(parser)
    parser.add_argument('mac')


def add_bulk_operation_args(parser):
    parser.add_argument('filepath', help='path to csv file containing record info')
    parser.add_argument('-c', '--creds', help='filepath to read in json credentials')
    me_group= parser.add_mutually_exclusive_group()
    me_group.add_argument('--create', action='store_true', help='create all records in csv, default action')
    me_group.add_argument('--delete', action='store_true', help='delete all records in csv')
    me_group.add_argument('--update', action='store_true', help='update all records in csv')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')


def main():
    # Main Argument Parser "pybluecat"
    parser = argparse.ArgumentParser(prog='Bluecat BAM CLI Tool')
    subparsers = parser.add_subparsers(title='Subcommands', help='subparsers command help')

    ## "pybluecat" sub-parser: "static"
    parser_static = subparsers.add_parser('static', help='static IP record manipulation')
    sub_static = parser_static.add_subparsers(title='Subcommands', help='options for static records')
    ## "pybluecat" sub-parser: "dhcp"
    parser_dhcp = subparsers.add_parser('dhcp', help='dhcp IP record manipulation')
    sub_dhcp = parser_dhcp.add_subparsers(title='Subcommands', help='options for dhcp records')
    ## "pybluecat" sub-parser: "search"
    parser_search = subparsers.add_parser('search', help='search BAM for Objects')
    sub_search = parser_search.add_subparsers(title='Subcommands', help='options for dhcp records')

    ### pybluecat static create
    parser_static_create = sub_static.add_parser('create', help='create a static IP reservation')
    add_single_operation_args(parser_static_create)

    ### pybluecat static delete
    parser_static_delete = sub_static.add_parser('delete', help='delete a static IP reservation')
    add_single_operation_args(parser_static_delete)

    ### pybluecat static update
    parser_static_update = sub_static.add_parser('update', help='update a static IP reservation')
    add_single_operation_args(parser_static_update)

    ### pybluecat static bulk
    parser_static_bulk = sub_static.add_parser('bulk', help='create bulk static records from csv')
    add_bulk_operation_args(parser_static_bulk)

    ### pybluecat dhcp create
    parser_dhcp_create = sub_dhcp.add_parser('create', help='create a dhcp IP reservation')
    add_dhcp_single_operation_args(parser_dhcp_create)
    parser_dhcp_create.set_defaults(func=create_dhcp)

    ### pybluecat dhcp delete
    parser_dhcp_delete = sub_dhcp.add_parser('delete', help='delete a dhcp IP reservation')
    add_dhcp_single_operation_args(parser_dhcp_delete)

    ### pybluecat dhcp update
    parser_dhcp_update = sub_dhcp.add_parser('update', help='update a dhcp IP reservation')
    add_dhcp_single_operation_args(parser_dhcp_update)

    ### pybluecat dhcp bulk
    parser_dhcp_bulk = sub_dhcp.add_parser('bulk', help='create bulk dhcp records from csv')
    add_bulk_operation_args(parser_dhcp_bulk)
    parser_dhcp_bulk.set_defaults(func=handle_dhcp_bulk)

    # Parse the args from any and all parsers
    args = parser.parse_args()

    # Setup BAM-CLI logger
    global logger
    logger = logging.getLogger('pybluecat-cli')
    loglevel = args.loglevel.upper()
    if loglevel in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
        level = getattr(logging, loglevel)
        logger.setLevel(level=level)
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)

    # Get credentials and client
    global creds
    creds = get_creds(args)
    global bluecat
    bluecat = get_client(loglevel=loglevel)

    # Run the relevant function
    output = args.func(args)
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
