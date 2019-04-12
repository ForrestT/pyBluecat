#!/usr/bin/python
import argparse
import json
import logging
import pybluecat
from ipaddress import ip_address, ip_network
from sys import exit


def print_ip_info(ip_obj, network):
    print('Hostname   : {}'.format(ip_obj['name']))
    print('MAC Address: {}'.format(ip_obj['properties']['macAddress']))
    print('IP Address: {}'.format(ip_obj['properties']['address']))
    print('Subnet Mask: {}'.format(str(network.netmask)))
    print('Gateway    : {}'.format(str(network.network_address + 1)))
    for key in ip_obj['properties']:
        pass


def search_mac(session, mac):
    formatted_mac = mac.replace('.', '').replace(':', '').replace('-', '')
    mac_entity = session.get_mac_address(formatted_mac)
    results = session.get_linked_entities(mac_entity['id'])
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname', help='hostname')
    parser.add_argument('mac_addr', help='MAC Address')
    parser.add_argument('ip_addr', help='IP desired for reservation, also defines the network if "first_available" flag is set')
    parser.add_argument('-c', '--creds', help='path to file containing credentials')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    parser.add_argument('--location', default='', help='Location of Device')
    parser.add_argument('--notes', default='', help='Additional notes about the reservation')
    parser.add_argument('--owner', default='', help='Owner of the device')
    parser.add_argument('--request_num', default='', help='ServiceDesk Request Number')
    parser.add_argument('--first_available', action='store_true', help='Use first available IP as fallback option')
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
    hostname = args.hostname
    mac = args.mac_addr.replace('.', '').replace(':', '').replace('-', '')
    ip = ip_address(unicode(args.ip_addr))
    action = 'MAKE_DHCP_RESERVED'
    creds = pybluecat.get_creds(args.creds)
    properties = {
        'Location': args.location,
        'Notes': args.notes,
        'Owner': args.owner,
        'RequestNum': args.request_num
    }
    output_object = {}

    # Initialize flow-control boolean vars
    deploy_needed = False
    ip_is_eligible = False
    mac_already_reserved = False
    desired_ip_reserved = False
    error_message = ''

    # Create instance using 'with' so cleanup of session is automatic
    with pybluecat.BAM(**creds) as bam:
        # Determine the Network of the IP Address
        try:
            logger.info('Getting Network info from ip: {}'.format(str(ip)))
            net_entity = bam.get_network(str(ip))
            net_obj = pybluecat.entity_to_json(net_entity)
            network = ip_network(unicode(net_obj['properties']['CIDR']))
            if network.prefixlen <= 24:
                dhcp_offset_ip = str(network.network_address + 31)
            else:
                dhcp_offset_ip = None
            logger.debug(json.dumps(net_obj, indent=2))
        except pybluecat.exceptions.BluecatError as e:
            logger.error('Could not determine the target network or network did not exist')
            exit(str(e))

        # Determine if IP eligible to be reserved, not Broadcast, Network, Gateway, etc...
        if ip == network.network_address:
            error_message = 'Cannot reserve the Network Address: {}'.format(str(ip))
            logger.info(error_message)
        elif ip == network.broadcast_address:
            error_message = 'Cannot reserve the Broadcast Address: {}'.format(str(ip))
            logger.info(error_message)
        elif ip == network.network_address + 1:
            error_message = 'Cannot reserve the Gateway Address: {}'.format(str(ip))
            logger.info(error_message)
        elif ip in [network.network_address + 2, network.network_address + 3]:
            error_message = 'Cannot reserve a GSLB/VRRP Address: {}'.format(str(ip))
            logger.info(error_message)
        elif network.prefixlen <= 24 and ip in [network.network_address + i for i in xrange(4, 31)]:
            error_message = 'Cannot reserve Address in Telecom-Reserved Space: {}'.format(str(ip))
            logger.info(error_message)
        else:
            ip_is_eligible = True

        # Determine if MAC is already associated with a reservation in target network
        logger.info('Searching for existing reservations for MAC: {}'.format(mac))
        try:
            linked_entities = search_mac(bam, mac)
            for entity in linked_entities:
                if entity['type'] == 'IP4Address':
                    ip_obj = pybluecat.entity_to_json(entity)
                    logger.debug(json.dumps(ip_obj, indent=2, sort_keys=True))
                    ip_obj_address = ip_address(unicode(ip_obj['properties']['address']))
                    # Break loop as soon as match is found, return the matched reservation
                    if ip_obj_address in network and ip_obj['properties']['state'] == 'DHCP_RESERVED':
                        logger.info('Found existing reservation in target network')
                        mac_already_reserved = True
                        output_object = {
                            'status': 'Found existing reservation',
                            'message': 'MAC Address has existing reservation in current network.',
                            'reservation': ip_obj
                        }
                        break
        # If MAC not found handle the error, otherwise exit script with error code 1
        except pybluecat.exceptions.BluecatError as e:
            if 'Object was not found' in e.message:
                logger.info('MAC address does not currently exist in Bluecat')
            else:
                logger.error('Failed searching for MAC')
                exit(str(e))

        # If we didn't find an existing reservation, try to get a new one
        if not mac_already_reserved:
            logger.info('MAC address has no current reservations in target network')
            # Try to create the Reservation using the literal IP given as arg
            if ip_is_eligible:
                logger.info('Sending reservation request to Bluecat for IP: {}'.format(str(ip)))
                try:
                    ip_id = bam.assign_ip_address(hostname, str(ip), mac, action, properties)
                    ip_entity = bam.get_entity_by_id(ip_id)
                    ip_obj = pybluecat.entity_to_json(ip_entity)
                    desired_ip_reserved = True
                    deploy_needed = True
                    output_object = {
                        'status': 'New Reservation Create',
                        'message': 'Desired IP Address was Available and Assigned',
                        'reservation': ip_obj
                    }
                # Handle Bluecat errors, shouldn't see anything other than Dupes at this point
                except pybluecat.exceptions.BluecatError as e:
                    if 'Duplicate' in e.message:
                        error_message = 'Desired IP is already in Use'
                        logger.info(error_message)
                        ip_entity = bam.get_ip_address(str(ip))
                        conflicting_ip = pybluecat.entity_to_json(ip_entity)
                    elif 'already used by another IP within the same network' in e.message:
                        # Should've been caught earlier
                        error_message = e.message
                        logger.error(error_message)
                    else:
                        # Probably a system failure :(
                        logger.error(e.message)

            # If we were not able to reserve the desired IP for whatever reason...
            if not desired_ip_reserved:
                # Get next available IP if flag is set
                if args.first_available:
                    try:
                        logger.info('Sending request to Bluecat to assign next available address in network: {}'.format(str(network)))
                        ip_entity = bam.assign_next_ip_address(net_obj['id'], hostname, mac, action, properties, dhcp_offset_ip)
                        ip_obj = pybluecat.entity_to_json(ip_entity)
                        logger.debug(json.dumps(ip_obj, indent=2, sort_keys=True))
                        output_object = {
                            'status': 'New Reservation Created',
                            'message': [
                                error_message,
                                'First Available IP Address was assigned'
                            ],
                            'reservation': ip_obj
                        }
                        deploy_needed = True
                    # Expected errors here would be network out of addresses
                    except pybluecat.exceptions.BluecatError as e:
                        output_object = {
                            'status': 'Reservation could not be completed',
                            'message': [
                                error_message,
                                e.message
                            ]
                        }
                        logger.error('Unable to assign next available IP address')
                # Should hit this only when target IP in ineligible and __first_available is not set
                else:
                    output_object = {
                        'status': 'Reservation could not be completed',
                        'message': [
                            error_message,
                            'Try using the --first_available flag or choose a different IP Address'
                        ],
                        'conflicting_ip': conflicting_ip
                    }

        # Deploy DHCP changes if no_deploy flag isn't set
        if deploy_needed and not args.no_deploy:
            logger.info('Deploying Config changes')
            server_set = bam.queue_servers(net_obj['id'])
            for server in server_set:
                logger.info('Deploying changes to server: {}'.format(str(server)))
                bam.deploy_server_services(server, 'DHCP')
            # Monitor the deployment through completion unless no_wait flag is set
            if not args.no_wait:
                logger.info('Waiting for deployment to finish')
                bam.monitor_server_deployment(server_set)
                logger.info('Deployment finished')
            else:
                logger.info('Monitoring of deployment is being skipped')

    # Finally output the IP info
    #print_ip_info(ip_obj)
    print(json.dumps(output_object, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

