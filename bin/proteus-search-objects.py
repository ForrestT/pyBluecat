#!/usr/bin/python
from proteus import SOAPClient
import argparse
import json


def set_prop(field, props):
    """ensure that some value is always set"""
    if field in props:
        return props[field]
    else:
        return ''

parser = argparse.ArgumentParser()
parser.add_argument('objType', help='Object Type: IP4Address, IP4Network, etc')
parser.add_argument('searchstring', help='string to search for')
parser.add_argument('-s', '--size', type=int, help='size of each request to Proteus')
parser.add_argument('-m', '--max', type=int, help='max number of results to return')
parser.add_argument('-c', '--creds', help='path to file containing credentials')
args = parser.parse_args()

# Ensure rSize and rMax are set, and that rSize is not greater than rMax
if args.size:
    rSize = args.size
else:
    rSize = 1000
if args.max:
    rMax = args.max
    if rSize > rMax:
        rSize = rMax
else:
    rMax = 100000

# Load creds from file
with open(args.creds) as f:
    creds = json.load(f)

# Connect to Proteus, print header
s = SOAPClient(creds['username'], creds['password'])
print('name|address|macaddress|state|location|notes')
# Search in batches of 1000 until no more results or 100000 results returned
for i in xrange(0, rMax, rSize):
    # Get up to 1000 results
    try:
        results = s.searchByObjectTypes(args.searchstring, args.objType, i, rSize)
    except:
        raise
    # for each result, format and print info
    for result in results:
        # Skip if entity has no name
        if result.name is None:
            name = ''
        else:
            name = result.name.lower()
        # convert API object into serializable JSON, then print
        output = s.apiEntityToDict(result)
        print(json.dumps(output, indent=2))
    # If less than 1000 results are returned, discontinue search loop
    if len(results) < rSize:
        break
# Always logout :)
s.logout()
