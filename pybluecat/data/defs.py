#!/usr/bin/python
from pybluecat.data.helpers import *


class APIEntity(object):

    def __init__(id, type, name=None, value=None, properties=None):
        self.id = id
        self.type = type
        self.name = name
        self.value = value
        self.properties = properties_s2d(properties)

    def __str__(self):
        pass
