#!/usr/bin/python
"""Walk Proteus and output all subnets and associated info
"""
from proteus import SOAPClient
import argparse

# Adonis Server ID's
boxen = {
    557448: 'bl_main',
    557078: 'tis_main',
    1409301: 'bl_cache',
    1409299: 'bw_cache',
    3496238: 'gmh_dc',
    3497382: 'gmh_mdf',
    3620430: 'sbr_dc',
    3620427: 'sbr_mdf',
    3684294: 'slh_dc',
    3684296: 'slh_mdf',
    3548377: 'zch_dc',
    3549506: 'zch_2069',
    3722274: 'shp_dc',
    3722279: 'shp_mdf'
}


def getDHCP(session, netId):
    deployRoles = session.getDeploymentRoles(netId)
    if deployRoles.item[0]['service'] == 'DHCP':
        master = deployRoles.item[0]['serverInterfaceId']
        p = session.propertiesStringToDict(deployRoles.item[0]['properties'])
        secondary = p['secondaryServerInterfaceId']
        return {
            'master': boxen[int(master)],
            'secondary': boxen[int(secondary)],
            'inherited': p['inherited']
        }
    else:
        return None


def walkNetworks(session, start):
    blocks = session.getEntities(start.id, 'IP4Block', 0, 256)
    subnets = session.getEntities(start.id, 'IP4Network', 0, 256)
    if len(blocks) > 0:
        for block in blocks:
            walkNetworks(session, block)
    for subnet in subnets:
        dhcp = getDHCP(session, subnet.id)
        if dhcp:
            properties = session.propertiesStringToDict(subnet.properties)
            if args.server:
                if args.server in dhcp.values():
                    print('{},{},{},{},"{}"'.format(properties['CIDR'], dhcp['master'], dhcp['secondary'], dhcp['inherited'], subnet.name))
            else:
                print('{},{},{},{},"{}"'.format(properties['CIDR'], dhcp['master'], dhcp['secondary'], dhcp['inherited'], subnet.name))


parser = argparse.ArgumentParser()
parser.add_argument('cidr', help='CIDR to act as root for enumeration')
parser.add_argument('-c', '--creds', help='path to file containing credentials')
parser.add_argument('-s', '--server', help='filter by dhcp server')
args = parser.parse_args()

# ROOT_CIDR = '10.0.0.0/8'
ROOT_CIDR = args.cidr

with open(args.creds) as f:
    creds = json.load(f)

c = SOAPClient(creds['username'], creds['password'])
config = c.getEntityByName(0, 'Spectrum Health', 'Configuration')
startBlock = c.getEntityByCIDR(config.id, ROOT_CIDR, 'IP4Block')
walkNetworks(c, startBlock)
c.logout()
