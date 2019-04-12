#!/usr/bin/python
import argparse
import json
import logging
import pybluecat
from ipaddress import ip_address, ip_network
from sys import exit


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
            error_message = 'Cannot Update the Network Address: {}'.format(str(ip))
            logger.info(error_message)
        elif ip == network.broadcast_address:
            error_message = 'Cannot Update the Broadcast Address: {}'.format(str(ip))
            logger.info(error_message)
        elif ip == network.network_address + 1:
            error_message = 'Cannot Update the Gateway Address: {}'.format(str(ip))
            logger.info(error_message)
        elif ip in [network.network_address + 2, network.network_address + 3]:
            error_message = 'Cannot Update a HSRP/VRRP Address: {}'.format(str(ip))
            logger.info(error_message)
        elif network.prefixlen <= 24 and ip in [network.network_address + i for i in xrange(4, 31)]:
            error_message = 'Cannot Update Address in Telecom-Reserved Space: {}'.format(str(ip))
            logger.info(error_message)
        else:
            ip_is_eligible = True


        # Assuming the IP is eligible, attempt the update
        if ip_is_eligible:
            try:
                logger.info('Getting current config for IP: {}'.format(str(ip)))
                ip_entity = bam.get_ip_address(str(ip))
                old_reservation = pybluecat.entity_to_json(ip_entity)
                logger.debug(json.dumps(old_reservation, indent=2, sort_keys=True))
                if old_reservation['properties'] is None:
                    output_object = {
                        'state': 'No Update Performed',
                        'message': 'Target IP is not a DHCP_RESERVATION',
                        'existing_reservation': old_reservation
                    }
                elif old_reservation['properties']['state'] != 'DHCP_RESERVED':
                    output_object = {
                        'state': 'No Update Performed',
                        'message': 'Target IP is not a DHCP_RESERVATION',
                        'existing_reservation': old_reservation
                    }
                else:
                    response = bam.update_dhcp_reservation(old_reservation, hostname, mac, properties)
                    new_reservation = bam.get_ip_address(str(ip))
                    new_reservation = pybluecat.entity_to_json(new_reservation)
                    logger.debug(json.dumps(old_reservation, indent=2, sort_keys=True))
                    output_object = {
                        'status': 'Reservation Updated Successfully',
                        'message': 'Target IP was updated',
                        'old_reservation': old_reservation,
                        'new_reservation': new_reservation
                    }
                    deploy_needed = True
            except pybluecat.exceptions.BluecatError as e:
                output_object = {
                    'status': 'Error Occurred during Update',
                    'message': e.message
                }
        else:
            output_object = {
                'status': 'No Update Performed',
                'message': error_message
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

