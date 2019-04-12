import pybluecat.data.const
import pybluecat.data.helpers
from pybluecat.data.defs import *


DEPLOYMENT_STATUS = {
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

ADONIS_ID_MAP = {
    557447: 'BL-MAIN',
    5153278: 'BDC-NA-DHCPDNS-DC-1',
    557077: 'TIS-NA-DHCPDNS-DC-1',
    1409300: 'BL-NA-DNSCACHE-DC-1',
    1409298: 'BW-NA-DNSCACHE-DC-1',
    3496237: 'gmh-na-dhcpdns-dc-1',
    3497381: 'gmh-na-dhcpdns-2036a-1',
    3620429: 'sbr-na-dhcpdns-dc-1',
    3620426: 'sbr-na-dhcpdns-mdf-1',
    3684293: 'slh-na-dhcp-dc-1',
    3684295: 'slh-na-dhcp-mdf-1',
    3548376: 'zch-na-dhcp-dc-1',
    3549505: 'zch-na-dhcp-2069-1',
    3722273: 'shp-na-dhcp-dc-1',
    3722278: 'shp-na-dhcp-mdf-1'
}

ADONIS_PAIRS = {
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
