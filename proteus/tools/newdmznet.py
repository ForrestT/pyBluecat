#!/usr/bin/python
import argparse
import json
from ipaddress import ip_address, ip_network
from proteus import SOAPClient
from sys import exit


TIS_NETS = [
    ip_network(u'167.73.8.0/24'),
    ip_network(u'167.73.9.0/24')
]
BDC_NETS = [
    ip_network(u'167.73.24.0/24'),
    ip_network(u'167.73.25.0/24')
]


parser = argparse.ArgumentParser()
parser.add_argument('cidrPrefix', help='Size of CIDR Prefix, e.g. 28')
parser.add_argument('creds', help='path to file containing credentials')
args = parser.parse_args()


with open(args.creds) as f:
    creds = json.load(f)

c = SOAPClient(creds['username'], creds['password'])

for i in xrange(len(TIS_NETS)):
    tis = c.getIP4Block(str(TIS_NETS[i].network_address))
    tisSubnets = c.getEntities(tis['id'], 'IP4Network', 0, 256)
    bdc = c.getIP4Block(str(BDC_NETS[i].network_address))
    bdcSubnets = c.getEntities(bdc['id'], 'IP4Network', 0, 256)
    for subnet in tisSubnets:
        print(subnet.name)
    for subnet in bdcSubnets:
        print(subnet.name)
