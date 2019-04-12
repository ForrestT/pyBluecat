#!/usr/bin/python


def properties_s2d(self, propString):
    return {p[0]: p[1] for p in [pair.split('=') for pair in propString.split('|')[:-1]]}


def properties_d2s(self, propDict):
    return '|'.join(['='.join(pair) for pair in propDict.items()]) + '|'
