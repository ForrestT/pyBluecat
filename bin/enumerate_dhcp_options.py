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


def getDHCPOptions(session, entity):
    options = session.getDeploymentOptions(entity.id)
    for opt in options:
        if opt.name == 'dns-server':
            props = session.propertiesStringToDict(opt.properties)
            inherited = props['inherited']
            dns = opt.value
            break
    return [inherited, dns, entity.name]
    # properties = session.propertiesStringToDict(entity.properties)
    # print('{},{},{},"{}"'.format(properties['CIDR'], inherited, dns, entity.name))


def outputLine(name, fields):
    fields = [str(f) for f in fields]
    line = ','.join([name] + fields)
    print(line)


def walkNetworks(session, start):
    blocks = session.getEntities(start.id, 'IP4Block', 0, 256)
    subnets = session.getEntities(start.id, 'IP4Network', 0, 256)
    if len(blocks) > 0:
        for block in blocks:
            if any(block.name == wasteOfTime for wasteOfTime in ['OPEN', 'Available']):
                continue
            if not args.skipblocks:
                optInfo = getDHCPOptions(session, block)
                props = session.propertiesStringToDict(block.properties)
                outputLine(props['CIDR'], optInfo)
            walkNetworks(session, block)
    if not args.skipnetworks:
        for subnet in subnets:
            optInfo = getDHCPOptions(session, subnet)
            props = session.propertiesStringToDict(subnet.properties)
            outputLine(props['CIDR'], optInfo)


parser = argparse.ArgumentParser()
parser.add_argument('cidr', help='CIDR to act as root for enumeration')
parser.add_argument('-c', '--creds', help='path to file containing credentials')
parser.add_argument('--skipblocks', help='skip IP4Block Objects', action='store_true')
parser.add_argument('--skipnetworks', help='skip IP4Network Objects', action='store_true')
args = parser.parse_args()

with open(args.creds) as f:
    creds = json.load(f)

# init SOAP connection
c = SOAPClient(creds['username'], creds['password'])
# Get root config info
config = c.getEntityByName(0, 'Spectrum Health', 'Configuration')
optInfo = getDHCPOptions(c, config)
outputLine('Root Config', optInfo)
# Get starting IP Block info
startBlock = c.getEntityByCIDR(config.id, args.cidr, 'IP4Block')
if not args.skipblocks:
    optInfo = getDHCPOptions(c, startBlock)
    props = c.propertiesStringToDict(startBlock.properties)
    outputLine(props['CIDR'], optInfo)
# Walk the rest of the blocks/networks from start block
walkNetworks(c, startBlock)
c.logout()
