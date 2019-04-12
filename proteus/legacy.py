#!/usr/bin/python

from suds.client import Client
from time import sleep
from pprint import pprint
from dns import resolver, reversename
from os import system
import json

class Proteus:

  deployment_status = {-1: 'EXECUTING',
                        0: 'INITIALIZING',
                        1: 'QUEUED',
                        2: 'CANCELLED',
                        3: 'FAILED',
                        4: 'NOT_DEPLOYED',
                        5: 'WARNING',
                        6: 'INVALID',
                        7: 'DONE',
                        8: 'NO_RECENT_DEPLOYMENT'}

  # Adonis Server ID's
  bl_main = 557447
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
  adonis_pairs = {bl_main: tis_main,
                  tis_main: bl_main,
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
                  shp_mdf: shp_dc}

  def __init__(self, username='fthroescAPI', password='C1sc0123!', action='MAKE_STATIC'):
    self.url = 'http://proteus.spectrum-health.org/Services/API?wsdl'
    self.username = username #'fthroescAPI'
    self.password = password #'C1sc0123!'
    self.client = Client(self.url)
    self.login()
    self.config_name = 'Spectrum Health'
    self.config_id = self.getEntityByName(self.config_name, 'Configuration')['id']
    self.action = action
    self.network = IP4Network()
    self.servers_to_deploy = []

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

  def getEntityByName(self, name, item_type, parent_id=0):
    result = self.client.service.getEntityByName(parent_id, name, item_type)
    return result

  def getIP4Network(self, net_addr):
    result = self.client.service.getIPRangedByIP(self.config_id, 'IP4Network', net_addr)
    self.network.net_id = result['id']
    self.network.net_name = result['name']
    net_details = result['properties'].split('|')
    self.__getNetProperties(net_details)
    return net_details

  def __getNetProperties(self, net_details):
    for detail in net_details:
      if 'CIDR=' in detail:
        self.network.net_cidr = detail.split('=')[1]
        self.network.set_mask()
      elif 'gateway=' in detail:
        self.network.net_gw = detail.split('=')[1]
    temp = self.network.net_gw.split('.')
    temp[3] = str(int(temp[3]) + self.network.dhcp_offset)
    offset = '.'.join(temp)
    self.network.net_properties = 'offset=' + offset + '|excludeDHCPRange=' + self.network.dhcp_exclude

  def getIP4Address(self, ip_addr):
    return self.client.service.getIP4Address(self.config_id, ip_addr)

  def getNextIP4Address(self):
    return self.client.service.getNextIP4Address(self.network.net_id, self.network.net_properties)

  def assignIP4Address(self, hostname, ip_addr, mac_addr=''):
    hostname_str = 'name=' + hostname
    self.client.service.assignIP4Address(self.config_id, ip_addr, mac_addr, '', self.action, hostname_str)
    self.network.hostname = hostname
    self.network.ip_addr = ip_addr
    self.network.mac_addr = mac_addr
    return self.getIP4Address(ip_addr)

  def getDeploymentRoles(self):
    result = self.client.service.getDeploymentRoles(self.network.net_id)
    return result[0][0]['id']

  def getServerForRole(self, deploy_id):
    result = self.client.service.getServerForRole(deploy_id)
    server_id = result['id']
    server_name = result['name']
    return Pserver(server_name, server_id)

  def getBackupServer(self, server_id):
    backup_id = Proteus.adonis_pairs[server_id]
    result = self.client.service.getEntityById(backup_id)
    backup_name = result['name']
    return Pserver(backup_name, backup_id)

  def queueServers(self):
    deployment_id = self.getDeploymentRoles()
    server = self.getServerForRole(deployment_id)
    if server not in self.servers_to_deploy:
      self.servers_to_deploy.append(server)
      backup = self.getBackupServer(server.sid)
      self.servers_to_deploy.append(backup)

  def deployServerConfig(self):
    for server in self.servers_to_deploy:
      self.client.service.deployServerConfig(server.sid, 'services=DHCP')

  def __getDeploymentStatus(self):
    for server in self.servers_to_deploy:
      server.status = self.client.service.getServerDeploymentStatus(server.sid, '')

  def __getServerStatus(self, server):
    return self.client.service.getServerDeploymentStatus(server.sid, '')

  def __isDeploymentFinished(self):
    for server in self.servers_to_deploy:
      if server.status in [-1,0,1]:
        return False
    return True

  def monitorServerDeployment(self):
    self.__getDeploymentStatus()
    for server in self.servers_to_deploy:
      print('{} - {}'.format(server.name, Proteus.deployment_status[server.status]))
    while self.__isDeploymentFinished() == False:
      for server in self.servers_to_deploy:
        old_status = server.status
        server.status = self.__getServerStatus(server)
        if server.status != old_status:
          print('{} - {}'.format(server.name, Proteus.deployment_status[server.status]))
      sleep(2)

  def print_ip_info(self):
    j = self.network.get_json()
    print(json.dumps(j))

  def updateEntityProperties(self, entity, state):
    old_name = entity['name']
    properties = entity['properties']
    old_mac = properties.split('macAddress=')[1][:17]
    old_addr = properties.split('address=')[1].split('|')[0]
    old_state = properties.split('state=')[1].split('|')[0]
    properties = properties.replace(old_mac, self.network.mac_addr)
    properties = properties.replace(old_addr, self.network.ip_addr)
    properties = properties.replace(old_state, state)
    entity['name'] = self.network.hostname
    entity['properties'] = properties
    return entity

  def updateEntity(self, entity):
    self.client.service.update(entity)
    self.network.net_id = entity['id']

  def getMACAddress(self, mac_addr):
    result = self.client.service.getMACAddress(self.config_id, mac_addr)
    return result

  def getLinkedEntities(self, entity_id, max_results=10):
    results = self.client.service.getLinkedEntities(entity_id, 'IP4Address', 0, max_results)
    if results == '':
        return []
    else:
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

  ALL_ONES = 4294967295 # 2**32 - 1
  MASK_1 = 4278190080   # 2**24 * 255
  MASK_2 = 16711680   # 2**16 * 255
  MASK_3 = 65280      # 2**8  * 255
  MASK_4 = 255      # 2**0  * 255

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
    j = {'net_name':str(self.net_name),
        'hostname':str(self.hostname),
        'gateway':str(self.net_gw),
        'ip_addr':str(self.ip_addr),
        'mac_addr':str(self.mac_addr),
        'net_mask':str(self.net_mask)}
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
