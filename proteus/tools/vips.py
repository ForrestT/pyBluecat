#!/usr/bin/python
import argparse
import json
from ipaddress import ip_address
from proteus import SOAPClient
from sys import exit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname', help='hostname')
    parser.add_argument('creds', help='credentials file')
    group_ME = parser.add_mutually_exclusive_group(required=True)
    # group_ME.add_argument('-n', '--network', help='network address within desired subnet')
    group_ME.add_argument('-e', '--env', choices=['dmz', 'internal'], help='network environment')
    args = parser.parse_args()

    MASK = ip_address(u'0.0.0.255')
    NETWORK_ENVS = {
        'dmz': [
            {
                'tis': '167.73.15.0',
                'bdc': '167.73.31.0'
            }
        ],
        'internal': [
            {
                'tis': '10.7.26.0',
                'bdc': '10.107.26.0'
            }
        ]
    }

    hostname = args.hostname.lower()
    networkPairList = NETWORK_ENVS[args.env]
    with open(args.creds) as f:
        creds = json.load(f)
    c = SOAPClient(creds['username'], creds['password'])
    for networkPair in networkPairList:
        # Get Network Objects and set dhcp_offset based on env
        tisNetObj = c.getIP4Network(networkPair['tis'])
        bdcNetObj = c.getIP4Network(networkPair['bdc'])
        dhcp_offset = 30
        # Ensure Hostname doesn't already exist in Proteus
        foundIP = False
        for netObj in [tisNetObj, bdcNetObj]:
            response = c.getEntityByName(netObj['id'], hostname, 'IP4Address')
            if response['properties'] is not None:
                properties = c.propertiesStringToDict(response['properties'])
                ipObj = c.getIP4Address(properties['address'])
                foundIP = True
                break
                # print(json.dumps(ipObj, sort_keys=True, indent=4))
                # c.logout()
                # exit()
        # If an existing IP has not been found yet, start working through
        # every free IP in the Proteus Network until one is assigned or net is
        # exhausted
        if not foundIP:
            while True:
                tisIP = ip_address(c.getNextIP4Address(tisNetObj, offset=dhcp_offset))
                bdcIP = ip_address(c.getNextIP4Address(bdcNetObj, offset=dhcp_offset))
                if any(ip is None for ip in [tisIP, bdcIP]):
                    print('ERROR: out of IPs :(')
                    break
                tisNum = int(tisIP) & int(MASK)
                bdcNum = int(bdcIP) & int(MASK)
                if tisNum == bdcNum:
                    ipObj = c.assignIP4Address(hostname, str(tisIP))
                    print(json.dumps(ipObj, sort_keys=True, indent=4))
                    ipObj = c.assignIP4Address(hostname, str(bdcIP))
                    print(json.dumps(ipObj, sort_keys=True, indent=4))
                    exit()
                elif tisNum > bdcNum:
                    dhcp_offset = tisNum - 1
                else:
                    dhcp_offset = bdcNum - 1
            # while True:
            #     # None as a result indicates network has no next IP, end loop
            #     if tisIP is None:
            #         break
            #     # Check if IP has existing PTR record, if True, write it to Proteus, try next IP
            #     ptr = c.dns_PTR_exists(tisIP)
            #     if ptr:
            #         c.assignIP4Address(ptr, tisIP)
            #     # Try to Ping the IP address, if response, log in Proteus, try next IP
            #     elif c.ping(tisIP):
            #         c.assignIP4Address('IN-USE: something pinged', tisIP)
            #     # Finally, reserve the IP in Proteus for the hostname
            #     else:
            #         ipObj = c.assignIP4Address(hostname, ipAddr)
            #         foundIP = True
            #         break
        # If an IP has been found, either new or existing, return results and exit
        if foundIP:
            print(json.dumps(ipObj, sort_keys=True, indent=4))
            c.logout()
            exit()
    if not foundIP:
        print('No Addresses Available.')
        exit(1)

if __name__ == "__main__":
    main()
