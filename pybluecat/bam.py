#!/usr/bin/python
import requests
import json
import logging
from ipaddress import ip_address, ip_network
from pybluecat import data as DATA
from pybluecat.data import *
from pybluecat.exceptions import BluecatError
from time import sleep


class BAM:
    """About the Bluecat REST API:
    REST APIs have many similarities with the widely used SOAP-based APIs supported by Address
    Manager. However, there are a few differences between REST interface and existing SOAP
    implementation:
    - The names of API methods in REST remain the same as that of SOAP APIs.
    - Signatures of all methods including input and output parameters in REST are the same as in SOAP.
    - In REST API, various primitive request parameters such as int, long and String are expected as URL
    query parameters. Whereas in SOAP, all the request parameters are communicated as part of XML
    body.
    - Complex parameter types such as APIEntity or APIDeploymentOption need to be passed as a part of
    HTTP body of the call in JSON format.
    """

    # Constants
    PROXIES = {'http': None, 'https': None}
    IP_ACTION_VALUES = [
        'MAKE_STATIC',
        'MAKE_RESERVED',
        'MAKE_DHCP_RESERVED'
    ]

    def __init__(self, hostname=None, username=None, password=None, configName='Spectrum Health', loglevel='CRITICAL'):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.history = []
        self.lastCall = None
        self.loglevel = loglevel
        self.logger = self.set_loglevel('pybluecat', loglevel)
        self.py_logger = self.set_loglevel('py.warnings', loglevel)
        self.session = self.init_session()
        self.baseUrl = 'https://{h}/Services/REST/v1/'.format(h=hostname)
        if all(param is not None for param in [hostname, username, password]):
            self.login(hostname, username, password)
            self.config = self.getConfig()
        else:
            self.config = None

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.logout()

    def init_session(self, proxies={'http': None, 'https': None},
                     headers={'Content-Type': 'application/json'},
                     ssl_verify=False):
        session = requests.Session()
        session.proxies.update(proxies)
        session.headers.update(headers)
        session.verify = ssl_verify
        if not ssl_verify:
            logging.captureWarnings(True)
        return session

    def set_loglevel(self, logger_name, loglevel):
        logger = logging.getLogger(logger_name)
        loglevel = loglevel.upper()
        if loglevel in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
            level = getattr(logging, loglevel)
            # logging.basicConfig(level=level)
            logger.setLevel(level=level)
        console_handler = logging.StreamHandler()
        logger.addHandler(console_handler)
        return logger

    ################################################################
    # DECORATORS
    ################################################################

    def rest_call(httpMethod):
        def outer(func):
            def inner(self, *args, **kwargs):
                method, params, data = func(self, *args, **kwargs)
                url = self.baseUrl + method
                methodMap = {
                    'delete': self.session.delete,
                    'get': self.session.get,
                    'post': self.session.post,
                    'put': self.session.put
                }
                response = methodMap[httpMethod](url, params=params, json=data)
                self.logger.debug('Request URL: {}'.format(response.request.url))
                self.logger.debug('Response Code: {}'.format(response.status_code))
                self.lastCall = response
                self.history.append(response)
                # Handle non-200 responses
                if response.status_code != 200:
                    raise BluecatError(response)
                try:
                    data = response.json()
                    self.logger.debug('Response Body: {}'.format(json.dumps(data, indent=2, sort_keys=True)))
                except Exception:
                    data = response.content
                    self.logger.debug('Response Body: {}'.format(data))
                return data
            return inner
        return outer

    ################################################################
    # HELPERS
    ################################################################

    def prop_s2d(self, propString):
        if propString is None:
            return None
        else:
            return {p[0]: p[1] for p in [pair.split('=') for pair in propString.split('|')[:-1]]}

    def prop_d2s(self, propDict):
        if propDict is None:
            return None
        else:
            return '|'.join(['='.join(pair) for pair in propDict.items()]) + '|'

    def entity_to_json(self, entity):
        entity['properties'] = self.prop_s2d(entity['properties'])
        return entity

    def json_to_entity(self, entity):
        entity['properties'] = self.prop_d2s(entity['properties'])
        return entity

    ################################################################
    # GENERAL STUFF
    ################################################################

    def login(self, host, username, password):
        method = 'login'
        params = {
            'username': username,
            'password': password
        }
        try:
            response = self.session.get(self.baseUrl + method, params=params)
            self.logger.info(response.content)
            # authToken = response.text.split('BAMAuthToken: ')[1].split(' <- ')[0]
            authToken = response.text.split('-> ')[1].split(' <-')[0]
            self.session.headers.update({'Authorization': str(authToken)})
        except:
            self.logger.error('ERROR: Login Failed')
        return response

    @rest_call('get')
    def logout(self):
        method = 'logout'
        params = None
        data = None
        return method, params, data

    @rest_call('get')
    def get_entity_by_name(self, parentId, name, objType):
        method = 'getEntityByName'
        params = {
            'parentId': parentId,
            'name': name,
            'type': objType
        }
        data = None
        return method, params, data

    def getConfig(self):
        return self.get_entity_by_name(0, 'Spectrum Health', 'Configuration')

    @rest_call('get')
    def get_entities(self, parent_id, obj_type, start=0, count=1000):
        method = 'getEntities'
        params = {
            'parentId': parent_id,
            'type': obj_type,
            'start': start,
            'count': count
        }
        data = None
        return method, params, data

    def get_networks(self, parent_id, start=0, count=1000):
        return self.get_entities(parent_id, 'IP4Network', start, count)

    @rest_call('get')
    def get_entity_by_id(self, entityId):
        method = 'getEntityById'
        params = {
            'id': entityId
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_linked_entities(self, entityId, linkedType='IP4Address', start=0, count=100):
        method = 'getLinkedEntities'
        params = {
            'entityId': entityId,
            'type': linkedType,
            'start': start,
            'count': count
        }
        data = None
        return method, params, data

    @rest_call('delete')
    def delete(self, entity_id):
        method = 'delete'
        params = {
            'objectId': entity_id
        }
        data = None
        return method, params, data

    @rest_call('put')
    def update(self, entity):
        method = 'update'
        params = None
        data = entity
        return method, params, data

    def update_dhcp_reservation(self, entity, hostname, macAddr, properties):
        if isinstance(entity['properties'], str):
            entity = self.prop_s2d(entity)
        old_properties = entity['properties']
        if isinstance(properties, str):
            properties = self.prop_s2d(properties)
        new_entity = entity.copy()
        new_entity['name'] = hostname
        properties['state'] = old_properties['state']
        properties['address'] = old_properties['address']
        properties['macAddress'] = macAddr
        properties['locationInherited'] = old_properties['locationInherited']
        new_entity['properties'] = self.prop_d2s(properties)
        self.update(new_entity)

    ################################################################
    # SEARCHES
    ################################################################

    @rest_call('get')
    def search_by_object_types(self, keyword, obj_type, start=0, count=100):
        method = 'searchByObjectTypes'
        params = {
            'keyword': keyword,
            'types': obj_type,
            'start': start,
            'count': count
        }
        data = None
        return method, params, data

    def search_ip_by_name(self, keyword, start=0, count=100):
        return self.search_by_object_types(keyword, 'IP4Address', start, count)

    ################################################################
    # NETWORK STUFF
    ################################################################

    @rest_call('get')
    def get_entity_by_cidr(self, parent_id, cidr, objType):
        """config.id only works for top-level blocks, parent_id must literally be the parent obect's id"""
        method = 'getEntityByCIDR'
        params = {
            'parentId': parent_id,
            'cidr': cidr,
            'type': objType
        }
        data = None
        return method, params, data

    def get_network_by_cidr(self, parent_id, cidr):
        return self.get_entity_by_cidr(parent_id, cidr, 'IP4Network')

    def get_block_by_cidr(self, parent_id, cidr):
        return self.get_entity_by_cidr(parent_id, cidr, 'IP4Block')

    @rest_call('get')
    def get_ip_ranged_by_ip(self, parentId, ipAddr, objType):
        method = 'getIPRangedByIP'
        params = {
            'containerId': parentId,
            'type': objType,
            'address': ipAddr.split('/')[0]
        }
        data = None
        return method, params, data

    def get_network(self, netAddr):
        return self.get_ip_ranged_by_ip(self.config['id'], netAddr, 'IP4Network')

    def get_network_by_ip(self, netAddr):
        return self.get_ip_ranged_by_ip(self.config['id'], netAddr, 'IP4Network')

    def get_block_by_ip(self, netAddr):
        return self.get_ip_ranged_by_ip(self.config['id'], netAddr, 'IP4Block')

    def get_dhcp_scope_by_ip(self, netAddr):
        return self.get_ip_ranged_by_ip(self.config['id'], netAddr, 'DHCP4Range')

    ################################################################
    # IP ADDRESS STUFF
    ################################################################

    @rest_call('get')
    def get_ip_address(self, ipAddr, parentId=None):
        method = 'getIP4Address'
        params = {
            'containerId': self.config['id'] if parentId is None else parentId,
            'address': ipAddr
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_next_ip_address(self, netId, offset=None, dhcpExclude=True):
        method = 'getNextIP4Address'
        properties = 'excludeDHCPRange={}|'.format(str(dhcpExclude).lower())
        if offset is not None:
            properties += 'offset={}|'.format(offset)
        params = {
            'parentId': netId,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def assign_next_ip_address(self, parentId, hostname, macAddr=None, action='MAKE_STATIC', properties='', offset=None):
        method = 'assignNextAvailableIP4Address'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        properties += 'name={}|'.format(hostname)
        if offset is not None:
            properties += 'offset={}|'.format(offset)
        params = {
            'configurationId': self.config['id'],
            'parentId': parentId,
            'macAddress': macAddr,
            'hostInfo': '',
            'action': action,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def assign_ip_address(self, hostname, ipAddr, macAddr='', action='MAKE_STATIC', properties=''):
        method = 'assignIP4Address'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        properties += 'name={}|'.format(hostname)
        params = {
            'configurationId': self.config['id'],
            'ip4Address': str(ipAddr),
            'macAddress': macAddr,
            'hostInfo': '',
            'action': action,
            'properties': properties
        }
        data = None
        return method, params, data

    def assign_ip_address_pair(self, net1, net2, hostname1, hostname2=None):
        """Assigns matching addresses in two separate, but equal-sized, networks
        networks expected to be CIDR"""
        if hostname2 is None:
            hostname2 = hostname1
        # Get Network Objects and set dhcp_offset based on env
        net1 = ip_network(unicode(net1))
        net2 = ip_network(unicode(net2))
        if net1.netmask != net2.netmask:
            raise ValueError('net1 and net2 CIDR prefixes are not equal')
        bam_net_1 = self.get_network(str(net1.network_address))
        bam_net_2 = self.get_network(str(net2.network_address))
        if net1.prefixlen > 24:
            dhcp_offset = 1
        else:
            dhcp_offset = 31
        mask = int(net1.netmask) ^ 2**32-1  # mask to determine ip's place in network
        # Ensure Hostname doesn't already exist in BAM
        found_ip = False
        response1 = self.get_entity_by_name(bam_net_1['id'], hostname1, 'IP4Address')
        response2 = self.get_entity_by_name(bam_net_2['id'], hostname2, 'IP4Address')
        if any(r['properties'] is not None for r in [response1, response2]):
            bam_ip_list = [self.entity_to_json(response1), self.entity_to_json(response2)]
            found_ip = True
        # If hostname doesn't exist, begin looping through networks for available address pairs
        while not found_ip and dhcp_offset < mask:
            dhcp_offset1 = str(net1.network_address + dhcp_offset)
            dhcp_offset2 = str(net2.network_address + dhcp_offset)
            ip1 = ip_address(self.get_next_ip_address(bam_net_1['id'], offset=dhcp_offset1))
            ip2 = ip_address(self.get_next_ip_address(bam_net_2['id'], offset=dhcp_offset2))
            if any(ip is None for ip in [ip1, ip2]):
                print('ERROR: out of IPs :(')
                found_ip = True
            else:
                # use mask to determine the ip's network index, e.g. in 10.20.30.0/23 10.20.31.15 = 271
                num1 = int(ip1) & int(mask)
                num2 = int(ip2) & int(mask)
                # if the ip's have the same network index, go ahead with assignment
                if num1 == num2:
                    ipObj1 = self.assign_ip_address(hostname1, str(ip1))
                    ipObj2 = self.assign_ip_address(hostname2, str(ip2))
                    bam_ip_list = [ipObj1, ipObj2]
                    found_ip = True
                # if the ip's have different indexes, continue looking at the highest of the two indexes
                elif num1 > num2:
                    dhcp_offset = num1 - 1
                else:
                    dhcp_offset = num2 - 1
        return bam_ip_list

################################################################
# MAC ADDRESS STUFF
################################################################

    @rest_call('get')
    def get_mac_address(self, mac):
        method = 'getMACAddress'
        params = {
            'configurationId': self.config['id'],
            'macAddress': mac.replace('.', '').replace(':', '').replace('-', '')
        }
        data = None
        return method, params, data

    @rest_call('post')
    def create_mac_address(self, mac, name, properties):
        method = 'addMACAddress'
        if isinstance(properties, dict):
            properties_string = 'name={}|'.format(name) + self.prop_d2s(properties)
        else:
            properties_string = 'name={}|'.format(name) + properties
        params = {
            'configurationId': self.config['id'],
            'macAddress': mac.replace('.', '').replace(':', '').replace('-', ''),
            'properties': properties_string
        }
        data = None
        return method, params, data

################################################################
# ROLE AND DEPLOYMENT STUFF
################################################################

    @rest_call('get')
    def get_deployment_roles(self, entity_id):
        method = 'getDeploymentRoles'
        params = {
            'entityId': entity_id
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_server_for_role(self, role_id):
        method = 'getServerForRole'
        params = {
            'roleId': role_id
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_deployment_status(self, server_id):
        method = 'getServerDeploymentStatus'
        params = {
            'serverId': server_id,
            'properties': ''
        }
        data = None
        return method, params, data

    @rest_call('post')
    def deploy_server(self, server_id):
        method = 'deployServer'
        params = {
            'serverId': server_id
        }
        data = None
        return method, params, data

    @rest_call('post')
    def deploy_server_config(self, server_id, services='DHCP', full=False):
        method = 'deployServerConfig'
        properties = 'ObjectProperties.services={}'.format(services)
        if full and 'DNS' in service:
            properties += '|forceDNSFullDeployment=true'
        params = {
            'serverId': server_id,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def deploy_server_services(self, server_id, services='DHCP'):
        method = 'deployServerServices'
        params = {
            'serverId': server_id,
            'services': 'services={}'.format(services)
        }
        data = None
        return method, params, data

    def queue_servers(self, network_id, server_set=None):
        """Given a set and a network_id, determines the primary
        and backup servers for the network and adds them to the
        set. The resulting set is then returned.
        """
        if server_set is None:
            server_set = set()
        roles = self.get_deployment_roles(network_id)
        server_primary = self.get_server_for_role(roles[0]['id'])
        server_backup_id = DATA.ADONIS_PAIRS[server_primary['id']]
        server_set.add(server_primary['id'])
        server_set.add(server_backup_id)
        return server_set


    def deploy_dhcp_and_monitor(self, server_set):
        """Given a set of servers to deploy, each server will be
        deployed. The deployment status will be followed until all
        have terminated in some way.
        """
        for server in server_set:
            self.deploy_server_services(server, 'DHCP')
        self.monitor_server_deployment(server_set)


    def monitor_server_deployment(self, server_set):
        """Given a set of servers that have been deployed, the status
        of each will be continuously polled until all have reached a
        final state.
        """
        for server in server_set:
            status = self.get_deployment_status(server)
            self.logger.info('{} - {}'.format(DATA.ADONIS_ID_MAP[server], DATA.DEPLOYMENT_STATUS[status]))
        while len(server_set) > 0:
            sleep(2)
            servers = list(server_set)
            for server in servers:
                status = self.get_deployment_status(server)
                if status not in [-1, 0, 1]:
                    self.logger.info('{} - {}'.format(DATA.ADONIS_ID_MAP[server], DATA.DEPLOYMENT_STATUS[status]))
                    server_set.remove(server)

################################################################
# IF RUN DIRECTLY, MOSTLY FOR TESTING
################################################################

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('creds')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    args = parser.parse_args()
    # Load credentials
    with open(args.creds) as f:
        creds = json.load(f)
    # Enable logging if requested
    if args.loglevel:
        level = getattr(logging, args.loglevel.upper())
        logging.basicConfig(level=level)
    # Prove that client works
    c = BAM(creds['hostname'], creds['username'], creds['password'], loglevel=args.loglevel)
    net = c.get_network_by_ip('10.168.128.0')
    roles = c.get_deployment_roles(net['id'])
    r = c.get_next_ip_address(net['id'], offset='10.168.128.100')
    r = c.assign_next_ip_address(net['id'], 'offset-testing', offset='10.168.128.100')
    r = c.get_ip_address('10.97.12.69')
    c.logout()
    print(c.history)
    # print(data.ADONIS_PAIRS)
