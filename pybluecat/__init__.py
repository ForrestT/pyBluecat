import json
import os
from pybluecat.bam import BAM
from pybluecat.exceptions import *


def get_creds(filepath=None):
    if filepath is None:
        os_name = os.name
        if os_name == 'posix':
            filepath = os.environ['HOME'] + '/.bluecat'
        elif os_name == 'nt':
            filepath = os.environ['HOMEPATH'] + '\\.bluecat'
        else:
            filepath = '.bluecat'
    with open(filepath) as f:
        creds = json.load(f)
    if 'bluecat' in creds:
        creds = creds['bluecat']
    return creds

def prop_s2d(propString):
    if propString is None:
        return None
    else:
        return {p[0]: p[1] for p in [pair.split('=') for pair in propString.split('|')[:-1]]}

def prop_d2s(propDict):
    if propDict is None:
        return None
    else:
        return '|'.join(['='.join(pair) for pair in propDict.items()]) + '|'

def entity_to_json(entity):
    entity['properties'] = prop_s2d(entity['properties'])
    return entity

def json_to_entity(self, entity):
    entity['properties'] = prop_d2s(entity['properties'])
    return entity

