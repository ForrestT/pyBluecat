#!/usr/bin/python

from suds.client import Client
from time import sleep
from dns import resolver, reversename
from ipaddress import ip_address, ip_network
from os import system
import json


class SOAPClient:

    deployment_status = {
        -1: 'EXECUTING',
        0: 'INITIALIZING',
        1: 'QUEUED',
        2: 'CANCELLED',
        3: 'FAILED',
        4: 'NOT_DEPLOYED',
        5: 'WARNING',
        6: 'INVALID',
        7: 'DONE',
        8: 'NO_RECENT_DEPLOYMENT'
    }

    # Adonis Server ID's
    bl_main = 557447
    bdc_main = 5153278
    tis_main = 557077
    bl_cache = 1409300
    bw_cache = 1409298
    gmh_dc = 3496237
    gmh_mdf = 3497381
    sbr_dc = 3620429
    sbr_mdf = 3620426
    slh_dc = 3684293
    slh_mdf = 3684295
    zch_dc = 3548376
    zch_2069 = 3549505
    shp_dc = 3722273
    shp_mdf = 3722278
    adonis_pairs = {
        bdc_main: tis_main,
        tis_main: bdc_main,
        bl_cache: bw_cache,
        bw_cache: bl_cache,
        gmh_dc: gmh_mdf,
        gmh_mdf: gmh_dc,
        sbr_dc: sbr_mdf,
        sbr_mdf: sbr_dc,
        slh_dc: slh_mdf,
        slh_mdf: slh_dc,
        zch_dc: zch_2069,
        zch_2069: zch_dc,
        shp_dc: shp_mdf,
        shp_mdf: shp_dc
    }

    def __init__(self, username, password, action='MAKE_STATIC', config='Spectrum Health'):
        self.url = 'http://proteus.spectrum-health.org/Services/API?wsdl'
        self.username = username
        self.password = password
        self.client = Client(self.url)
        self.login()
        self.config_name = config
        self.config_id = self.getEntityByName(0, self.config_name, 'Configuration')['id']
        self.action = action
        self.network = IP4Network()
        self.servers_to_deploy = set()

    def ping(self, host):
        import subprocess
        try:
            r = subprocess.check_output(['ping', '-c', '1', host], stderr=subprocess.STDOUT)
            return True
        except subprocess.CalledProcessError:
            return False

    def dns_A_exists(self, host):
        try:
            a = resolver.query(host + '.spectrum-health.org', 'A')
            return a
        except:
            return None

    def dns_PTR_exists(self, host):
        try:
            ptr = reversename.from_address(host)
            name = resolver.query(ptr, 'PTR')[0]
            return str(name)
        except:
            return None

    def login(self):
        self.client.service.login(self.username, self.password)

    def logout(self):
        self.client.service.logout()

    def propertiesStringToDict(self, propString):
        return {p[0]: p[1] for p in [pair.split('=') for pair in propString.split('|')[:-1]]}

    def propertiesDictToString(self, propDict):
        return '|'.join(['='.join(pair) for pair in propDict.items()]) + '|'

    def searchByObjectTypes(self, keyword, objType, start=0, count=1000):
        result = self.client.service.searchByObjectTypes('^*' + keyword, objType, start, count)
        if result == '':
            return []
        return result[0]

    def getEntityById(self, entityId):
        result = self.client.service.getEntityById(entityId)
        return result

    def getEntities(self, parentId, objType, start, count):
        result = self.client.service.getEntities(parentId, objType, start, count)
        if result == '':
            return []
        return result[0]

    def getEntityByCIDR(self, parentId, cidr, objType):
        result = self.client.service.getEntityByCIDR(parentId, cidr, objType)
        return result

    def getEntityByName(self, parentId, name, objType):
        result = self.client.service.getEntityByName(parentId, name, objType)
        return result

    def getIP4Network(self, net_addr):
        result = self.client.service.getIPRangedByIP(self.config_id, 'IP4Network', net_addr)
        network = {
            'id': result.id,
            'name': result.name,
            'type': result.type,
            'properties': self.propertiesStringToDict(result.properties)
        }
        return network

    def getIP4Block(self, net_addr):
        result = self.client.service.getIPRangedByIP(self.config_id, 'IP4Block', net_addr)
        network = {
            'id': result.id,
            'name': result.name,
            'type': result.type,
            'properties': self.propertiesStringToDict(result.properties)
        }
        return network

    def ipObjToDict(self, ipObj):
        objDict = {
            'id': ipObj.id,
            'name': ipObj.name,
            'type': ipObj.type,
            'properties': self.propertiesStringToDict(ipObj.properties)
        }
        return objDict

    def apiEntityToDict(self, entity):
        entityDict = {
            'id': entity.id,
            'name': entity.name,
            'type': entity.type,
            'properties': self.propertiesStringToDict(entity.properties)
        }
        return entityDict

    def getIP4Address(self, ipAddr):
        result = self.client.service.getIP4Address(self.config_id, ipAddr)
        return self.apiEntityToDict(result)

    def getNextIP4Address(self, network, offset=30, dhcpExclude=True):
        octects = network['properties']['gateway'].split('.')
        octects[-1] = str(int(octects[-1]) + offset)
        offset = '.'.join(octects)
        options = 'offset={}|excludeDHCPRange={}'.format(str(offset), str(dhcpExclude))
        return self.client.service.getNextIP4Address(network['id'], options)

    def assignNextAvailableIP4Address(self, hostname, parentId, macAddr='', action='MAKE_STATIC', properties=''):
        """Assigns the Next Available IP in the given network

        hostname (string) = the hostname
        ipAddr (string) = the IPv4 Address to assign
        macAddr (string) = MAC Address, OPTIONAL if action is MAKE_STATIC
        action (string) = can be MAKE_STATIC, MAKE_RESERVED, MAKE_DHCP_RESERVED
        properties (dict) = key=value pairs
        """
        properties += 'name=' + hostname
        try:
            ipObj = self.client.service.assignNextAvailableIP4Address(self.config_id, parentId, macAddr, '', action, properties)
        except:
            raise
        return ipObj

    def assignIP4Address(self, hostname, ipAddr, macAddr='', action='MAKE_STATIC', properties=''):
        """Assigns the Specified IP Address the given info

        hostname (string) = the hostname
        ipAddr (string) = the IPv4 Address to assign
        macAddr (string) = MAC Address, OPTIONAL if action is MAKE_STATIC
        action (string) = can be MAKE_STATIC, MAKE_RESERVED, MAKE_DHCP_RESERVED
        properties (dict) = key=value pairs
        """
        properties += 'name=' + hostname
        try:
            self.client.service.assignIP4Address(self.config_id, ipAddr, macAddr, '', action, properties)
            ipObj = self.getIP4Address(ipAddr)
        except:
            raise
        return ipObj

    def assignIP4AddressPair(self, net1, net2, hostname1, hostname2=None):
        """Assigns matching addresses in two separate networks
        networks expected to be CIDR"""
        if hostname2 is None:
            hostname2 = hostname1
        # Get Network Objects and set dhcp_offset based on env
        net1 = ip_network(unicode(net1))
        net2 = ip_network(unicode(net2))
        if net1.netmask != net2.netmask:
            return 'CIDR prefixes don\'t match you dum fuk'
        netObj1 = self.getIP4Network(str(net1.network_address))
        netObj2 = self.getIP4Network(str(net2.network_address))
        dhcp_offset = 30  # cause I'm lazy
        MASK = int(net1.netmask) ^ 2**32-1
        # Ensure Hostname doesn't already exist in Proteus
        foundIP = False
        response1 = self.getEntityByName(netObj1['id'], hostname1, 'IP4Address')
        response2 = self.getEntityByName(netObj2['id'], hostname2, 'IP4Address')
        if any(r['properties'] is not None for r in [response1, response2]):
            ipObjList = [self.ipObjToDict(response1), self.ipObjToDict(response2)]
            foundIP = True
        while not foundIP:
            ip1 = ip_address(self.getNextIP4Address(netObj1, offset=dhcp_offset))
            ip2 = ip_address(self.getNextIP4Address(netObj2, offset=dhcp_offset))
            if any(ip is None for ip in [ip1, ip2]):
                print('ERROR: out of IPs :(')
                foundIP = True
            else:
                num1 = int(ip1) & int(MASK)
                num2 = int(ip2) & int(MASK)
                if num1 == num2:
                    ipObj1 = self.assignIP4Address(hostname1, str(ip1))
                    ipObj2 = self.assignIP4Address(hostname2, str(ip2))
                    ipObjList = [ipObj1, ipObj2]
                    foundIP = True
                elif num1 > num2:
                    dhcp_offset = num1 - 1
                else:
                    dhcp_offset = num2 - 1
        return ipObjList

    def getDeploymentRoles(self, networkId):
        result = self.client.service.getDeploymentRoles(networkId)
        return result

    def getDeploymentOptions(self, entityId):
        result = self.client.service.getDeploymentOptions(entityId, '', 0)
        return result.item

    def getServerForRole(self, deploy_id):
        result = self.client.service.getServerForRole(deploy_id)
        return result

    def getBackupServer(self, server_id):
        backup_id = Proteus.adonis_pairs[server_id]
        result = self.client.service.getEntityById(backup_id)
        backup_name = result['name']
        return Pserver(backup_name, backup_id)

    def queueServers(self, netObj):
        roles = self.getDeploymentRoles(netObj['id'])
        server1 = self.getServerForRole(roles.item[0].id)
        sid2 = self.adonis_pairs[server1.id]
        server2 = self.getEntityById(sid2)
        self.servers_to_deploy.add(server1)
        self.servers_to_deploy.add(server2)

    def deployQueuedServers(self):
        for server in self.servers_to_deploy:
            self.client.service.deployServerConfig(server.id, 'services=DHCP')

    def getDeploymentStatus(self, server):
        response = self.client.service.getServerDeploymentStatus(server.id, '')
        return response

    def getServerStatus(self, server):
        return self.client.service.getServerDeploymentStatus(server.id, '')

    def isDeploymentFinished(self):
        for server in self.servers_to_deploy:
            if server.status in [-1, 0, 1]:
                return False
        return True

    def monitorServerDeployment(self):
        for server in self.servers_to_deploy:
            status = self.getDeploymentStatus(server)
            print('{} - {}'.format(server.name, self.deployment_status[status]))
        while len(self.servers_to_deploy) > 0:
            sleep(2)
            servers = list(self.servers_to_deploy)
            for server in servers:
                status = self.getDeploymentStatus(server)
                if status not in [-1, 0, 1]:
                    print('{} - {}'.format(server.name, self.deployment_status[status]))
                    self.servers_to_deploy.remove(server)

    def print_ip_info(self):
        j = self.network.get_json()
        print(json.dumps(j))

    def macStrip(self, mac):
        return mac.replace('.', '').replace(':', '').replace('-', '')

    def macInsert(self, mac, delimiter):
        return delimiter.join([mac[i:i+2].upper() for i in [0, 2, 4, 6, 8, 10]])

    def updateEntityProperties(self, oldEntity, name, mac, state):
        newEntity = self.client.factory.create('APIEntity')
        newEntity['name'] = name
        newEntity['id'] = oldEntity['id']
        newEntity['type'] = oldEntity['type']
        props = {k: v for k, v in oldEntity['properties'].items()}
        props['macAddress'] = self.macInsert(mac, '-')
        props['state'] = state
        newEntity['properties'] = self.propertiesDictToString(props)
        return newEntity

    def updateEntity(self, entity):
        result = self.client.service.update(entity)
        return result

    def getMACAddress(self, mac_addr):
        result = self.client.service.getMACAddress(self.config_id, mac_addr)
        return result

    def getLinkedEntities(self, entity_id, max_results=10):
        results = self.client.service.getLinkedEntities(entity_id, 'IP4Address', 0, max_results)
        return results[0]

    def deleteEntity(self, entity_id):
        self.client.service.delete(entity_id)


class Pserver:

    def __init__(self, name, sid):
        self.name = name
        self.sid = sid
        self.status = 8

    def __repr__(self):
        return "Name: {}, Id: {}".format(self.name, self.sid)

    def __eq__(self, other):
        return self.sid == other.sid


class IP4Network:

    ALL_ONES = 4294967295  # 2**32 - 1
    MASK_1 = 4278190080    # 2**24 * 255
    MASK_2 = 16711680      # 2**16 * 255
    MASK_3 = 65280         # 2**8  * 255
    MASK_4 = 255           # 2**0  * 255

    def __init__(self):
        self.net_id = ''
        self.net_name = ''
        self.net_gw = ''
        self.net_mask = ''
        self.net_cidr = ''
        self.dhcp_offset = 30
        self.dhcp_exclude = 'True'
        self.net_properties = ''
        self.hostname = ''
        self.ip_addr = ''
        self.mac_addr = ''

    def __repr__(self):
        output = """
            Network Name : {}
            Network Id   : {}
            Network GW   : {}
            Network Mask : {}
            Network CIDR : {}
            Assigned IP  : {}
            DHCP Offset  : {}
            DHCP Exclude : {}
            Network Prop : {}
            """.format(self.net_name, self.net_id, self.net_gw, self.net_mask, self.net_cidr,
                       self.ip_addr, self.dhcp_offset, self.dhcp_exclude, self.net_properties)
        return output

    def get_json(self):
        j = {
            'net_name': str(self.net_name),
            'hostname': str(self.hostname),
            'gateway': str(self.net_gw),
            'ip_addr': str(self.ip_addr),
            'mac_addr': str(self.mac_addr),
            'net_mask': str(self.net_mask)
        }
        return j

    def int_to_ipv4(self, num):
        o = []
        o.append(str(num >> 24 & 255))
        o.append(str(num >> 16 & 255))
        o.append(str(num >> 8 & 255))
        o.append(str(num & 255))
        ip = '.'.join(o)
        return ip

    def cidr_to_mask(self, cidr):
        num = IP4Network.ALL_ONES ^ (2**(32-cidr) - 1)
        mask = self.int_to_ipv4(num)
        return mask

    def set_mask(self):
        cidr = int(self.net_cidr.split('/')[1])
        self.net_mask = self.cidr_to_mask(cidr)
