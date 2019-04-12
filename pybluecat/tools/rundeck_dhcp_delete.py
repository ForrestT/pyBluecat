#!/usr/bin/python
import argparse
import json
import logging
import pybluecat
from ipaddress import ip_address, ip_network
from sys import exit


def format_mac(mac):
    return mac.replace('.', '').replace(':', '').replace('-', '').lower()


def search_mac(session, mac):
    formatted_mac = format_mac(mac)
    mac_entity = session.get_mac_address(formatted_mac)
    results = session.get_linked_entities(mac_entity['id'])
    return results


def is_ip_off_limits(ip, network):
    off_limits = True
    error_message = ''
    # Determine if IP eligible to be reserved, not Broadcast, Network, Gateway, etc...
    if ip == network.network_address:
        error_message = 'Cannot Delete the Network Address: {}'.format(str(ip))
        logger.info(error_message)
    elif ip == network.broadcast_address:
        error_message = 'Cannot Delete the Broadcast Address: {}'.format(str(ip))
        logger.info(error_message)
    elif ip == network.network_address + 1:
        error_message = 'Cannot Delete the Gateway Address: {}'.format(str(ip))
        logger.info(error_message)
    elif ip in [network.network_address + 2, network.network_address + 3]:
        error_message = 'Cannot Delete a HSRP/VRRP Address: {}'.format(str(ip))
        logger.info(error_message)
    elif network.prefixlen <= 24 and ip in [network.network_address + i for i in xrange(4, 31)]:
        error_message = 'Cannot Delete Address in Telecom-Reserved Space: {}'.format(str(ip))
        logger.info(error_message)
    else:
        off_limits = False
    return off_limits, error_message


def main():
    parser = argparse.ArgumentParser()
    field_group = parser.add_argument_group('Matchable Fields', 'Provide at least one of the following fields to delete a reservation')
    parser.add_argument('--hostname', help='hostname of reservation(s) to delete')
    parser.add_argument('--mac_addr', help='MAC Address of reservation(s) to delete')
    parser.add_argument('--ip_addr', help='IP Address of reservation to delete')
    match_group = parser.add_mutually_exclusive_group(required=True)
    match_group.add_argument('--match_all', action='store_true', help='Delete only objects that match ALL conditions')
    match_group.add_argument('--match_any', action='store_true', help='Delete any object that matches ANY condition')
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    parser.add_argument('--no_wait', action='store_true', help='do NOT wait for deployment')
    parser.add_argument('--no_deploy', action='store_true', help='Do NOT deploy saved changes')
    args = parser.parse_args()

    # Setup console logging
    logger = logging.getLogger(__name__)
    loglevel = getattr(logging, args.loglevel.upper())
    logger.setLevel(level=loglevel)
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)
    logger.propagate = False

    # Setup args and vars
    # None values are passed along to be ignored later
    # Rundeck passes in empty strings instead, so translate those to None
    if args.hostname is not None:
        if args.hostname.strip() == '':
            hostname = None
        else:
            hostname = args.hostname
    else:
        hostname = None
    if args.mac_addr is not None:
        if args.mac_addr.strip() == '':
            mac = None
        else:
            mac = format_mac(args.mac_addr)
    else:
        mac = None
    if args.ip_addr is not None:
        if args.ip_addr.strip() == '':
            ip = None
        else:
            ip = ip_address(unicode(args.ip_addr))
    else:
        ip = None
    creds = pybluecat.get_creds(args.creds)
    output_object = {
        'status': '',
        'message': [],
        'deleted_reservations': []
    }

    # Exit Immediately if no fields were provided
    if all(field is None for field in [hostname, mac, ip]):
        output_object['status'] = 'No Reservations were Deleted'
        output_object['message'].append('No Fields were populated')
        output_object['message'].append('Please provided at least a Hostname, MAC_Address, or IP_Address')
        print(json.dumps(output_object, indent=2, sort_keys=True))
        exit()

    # Initialize flow-control boolean vars
    deploy_needed = False
    ip_is_eligible = False
    error_message = ''
    ips_seen_so_far = []
    candidate_reservations = []
    reservations_to_delete = []
    deleted_reservations = []

    # Create instance using 'with' so cleanup of session is automatic
    with pybluecat.BAM(**creds) as bam:
        # Get reservation matching the hostname, if given
        if hostname is not None:
            logger.info('Hostname provided ({}), searching for reservations'.format(hostname))
            results = bam.search_ip_by_name(hostname)
            logger.debug(json.dumps(results, indent=2, sort_keys=True))
            candidate_reservations += results
        # Get reservations matching the IP Address, if given
        if ip is not None:
            logger.info('IP Address provided ({}), searching for reservations'.format(str(ip)))
            result = bam.get_ip_address(str(ip))
            logger.debug(json.dumps(result, indent=2, sort_keys=True))
            candidate_reservations.append(result)
        # Get reservations matching the MAC Address, if given
        if mac is not None:
            logger.info('MAC Address provided ({}), searching for reservations'.format(args.mac_addr))
            results = search_mac(bam, mac)
            logger.debug(json.dumps(results, indent=2, sort_keys=True))
            candidate_reservations += results

        # Determine which of the matched reservations qualify for deletion
        logger.info('Checking all gathered reservations for deletion eligibility')
        for reservation in candidate_reservations:
            reservation = pybluecat.entity_to_json(reservation)
            # Skip NULL objects, can happen when MAC searches turn up nothing
            if reservation['properties'] is None:
                logger.info('Ignoring NULL object')
                continue
            # Gather details about the ip_object
            res_name = reservation['name']
            res_ip = reservation['properties']['address']
            if 'macAddress' in reservation['properties']:
                res_mac = reservation['properties']['macAddress']
            else:
                res_mac = ''
            logger.info('NAME: {}, IP: {}, MAC: {}'.format(res_name, res_ip, res_mac))
            # If IP Object state is not "DHCP_RESERVED" DO NOT DELETE
            if reservation['properties']['state'] != 'DHCP_RESERVED':
                logger.info('Reservation ineligible for deletion, ignoring objects with state: {}'.format(reservation['properties']['state']))
                continue
            # Ignore duplicate objects from the multiple searches
            if res_ip in ips_seen_so_far:
                logger.info('Duplicate entry for IP {}, skipping'.format(res_ip))
                continue
            # If --match_all is set, ensure ALL set fields match the reservation
            if args.match_all:
                # If --hostname is set and doesn't match, skip to next reservation
                if hostname is not None and res_name.lower() != hostname.lower():
                    logger.info('Reservation doesn\'t match --hostname filter with --match_all set, ineligible for deletion')
                    continue
                # If --ip_addr is set and doesn't match, skip to next reservation
                if ip is not None and res_ip != str(ip):
                    logger.info('Reservation doesn\'t match --ip_addr filter with --match_all set, ineligible for deletion')
                    continue
                # If --mac_addr is set and doesn't match, skip to next reservation
                if mac is not None and format_mac(res_mac) != mac:
                    logger.info('Reservation doesn\'t match --mac_addr filter with --match_all set, ineligible for deletion')
                    continue
            # Determine the Network of the IP Address
            try:
                logger.info('Getting Network info from ip: {}'.format(res_ip))
                net_entity = bam.get_network(res_ip)
                net_obj = pybluecat.entity_to_json(net_entity)
                network = ip_network(unicode(net_obj['properties']['CIDR']))
                logger.debug(json.dumps(net_obj, indent=2))
            except pybluecat.exceptions.BluecatError as e:
                # This would be really odd... But try to continue with the other reservations
                logger.error('Could not determine the target network or network did not exist')
                logger.error(e.message)
                continue
            # Continue on with either all reservations (if --match_any) or whatever is left from the --match_all block
            off_limits, error_message = is_ip_off_limits(res_ip, network)
            if off_limits:
                logger.info('Reservation ineligible for deletion: {}'.format(error_message))
                continue
            # Finally, mark the reservation for deletion
            reservations_to_delete.append((reservation, net_obj))
            ips_seen_so_far.append(res_ip)

        # Start deleting!
        for reservation, net_obj in reservations_to_delete:
            logger.info('Deleting DHCP Reservation: {}'.format(json.dumps(reservation, indent=2, sort_keys=True)))
            response = bam.delete(reservation['id'])
            output_object['deleted_reservations'].append(reservation)
            output_object['message'].append('DELETED: {}, {}'.format(reservation['properties']['address'], reservation['name']))
            deleted_reservations.append((reservation, net_obj))
        if len(deleted_reservations) > 0:
            deploy_needed = True
            output_object['status'] = 'Reservations have been deleted, config NOT deployed'
        else:
            output_object['status'] = 'No Reservations were Deleted'

        server_set = set()
        # Deploy DHCP changes if no_deploy flag isn't set
        if deploy_needed and not args.no_deploy:
            # Build unique set of DHCP servers
            logger.info('Gathering list of BAM servers to push updated configs to')
            for reservation, net_obj in deleted_reservations:
                server_set = server_set | bam.queue_servers(net_obj['id'])
            # Deploy changes to all servers in set
            logger.info('Deploying Config changes')
            for server in server_set:
                logger.info('Deploying changes to server: {}'.format(str(server)))
                bam.deploy_server_services(server, 'DHCP')
                output_object['message'].append('Server {} queued for deployment'.format(str(server)))
            # Monitor the deployment through completion unless no_wait flag is set
            if not args.no_wait:
                logger.info('Waiting for deployment to finish')
                bam.monitor_server_deployment(server_set)
                output_object['status'] = 'Reservations have been deleted, configs have been deployed'
                logger.info('Deployment finished')
            else:
                output_object['status'] = 'Reservations have been deleted, configs queued for deployment'
                logger.info('Monitoring of deployment is being skipped')

    # Finally output the IP info
    print(json.dumps(output_object, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

