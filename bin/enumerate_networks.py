#!/usr/bin/python
"""Walk Proteus and output all subnets and associated info
"""
from proteus import SOAPClient
import argparse
import json


def getLine(session, netObj):
    properties = session.propertiesStringToDict(netObj.properties)
    cidr = properties['CIDR'] if 'CIDR' in properties else ''
    vlan = properties['Vlan'] if 'Vlan' in properties else ''
    loc = properties['Location'] if 'Location' in properties else ''
    return '{c},"{n}",{t},{v},"{l}"'.format(c=cidr, n=netObj.name, t=netObj.type, v=vlan, l=loc)


def walkNetworks(session, start):
    blocks = session.getEntities(start.id, 'IP4Block', 0, 256)
    subnets = session.getEntities(start.id, 'IP4Network', 0, 256)
    if len(blocks) > 0:
        for block in blocks:
            print(getLine(session, block))
            walkNetworks(session, block)
    for subnet in subnets:
        print(getLine(session, subnet))

parser = argparse.ArgumentParser()
parser.add_argument('cidr', nargs='+', help='CIDR(s) to act as root for enumeration')
parser.add_argument('-a', '--append', help='omit header for appending to previous output', action='store_true')
parser.add_argument('-c', '--creds', help='path to file containing credentials')
args = parser.parse_args()

with open(args.creds) as f:
    creds = json.load(f)

c = SOAPClient(creds['username'], creds['password'])
config = c.getEntityByName(0, 'Spectrum Health', 'Configuration')

# startBlock = c.getIP4Block(ROOT_CIDR.split('/')[0])
if not args.append:
    print('Network,Name,Type,VLAN,Location')
for cidr in args.cidr:
    startBlock = c.getEntityByCIDR(config.id, cidr, 'IP4Block')
    print(getLine(c, startBlock))
    walkNetworks(c, startBlock)
c.logout()
