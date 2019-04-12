#!/usr/bin/python

from proteus import Proteus

hostname = 'Forrest-Test'
mac_addr = 'deadbeef0987'

p = Proteus()
#p.getIP4Network('10.168.161.1')
#ip_addr =  p.getNextIP4Address()
#p.assignIP4Address(hostname, ip_addr)
#p.queueServers()
#print p.network
#print p.servers_to_deploy
#p.deployServerConfig()
#p.monitorServerDeployment()
#p.logout()

e = p.getMACAddress(mac_addr)
r = p.getLinkedEntities(e)
for i in r:
  print i

p.logout()
