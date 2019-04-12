# Bluecat BAM API Wrapper #

## Installation ##

Supported on python 2.7, no promises on 3.x  

You can clone the repo, change to the top-level directory (with the setup.py file) and use pip to install the local files in "editable" mode (-e).

```bash
git clone https://github.com/ForrestT/pyBluecat.git
cd pybluecat
pip install --user .
```
- - - -
## How to Use ##

The library can be used within python

```python
import pybluecat

bam = pybluecat.BAM(hostname, username, password)  

network_obj = bam.get_network('10.97.12.0')

ip_obj = bam.get_ip_address('10.97.12.101')

bam.logout()
```
In an interactive python interpreter, use help() to play with the available methods
```python
>>> from pybluecat import BAM
>>> help(BAM)
```

You can also just use the CLI scripts interactively (use -h, --help)

```bash
bluecat --help

    usage: Bluecat CLI Tool [-h] {static,dhcp,search} ...

    optional arguments:
      -h, --help            show this help message and exit

    Subcommands:
      {static,dhcp,search}  subparsers command help
        static              static IP record manipulation
        dhcp                dhcp IP record manipulation
        search              search BAM for Objects

# Create a DHCP reservation
bluecat dhcp create <hostname> <mac> --network <networkAddress> --creds /location/of/creds.json

# Delete a STATIC IP reservation
bluecat static delete <ipAddress>
```

