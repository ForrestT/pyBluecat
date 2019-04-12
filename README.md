# Bluecat Proteus API Wrapper #

## Installation ##

Supported on python 2.7, no promises on 3.x  

You can clone the repo, change to the top-level directory (with the setup.py file) and use pip to install the local files in "editable" mode (-e).

```bash
git clone https://github.com/ForrestT/pyBluecat.git
cd proteus
pip install -e .
```
- - - -
## How to Use ##

The library can be used within python

```python
from proteus import RESTClient  

c = RESTClient(hostname, username, password)  

network_obj = c.get_network('10.97.12.0')

ip_obj = c.get_ip_address('10.97.12.101')

c.logout()
```
In an interactive python interpreter, use help() to play with the available methods
```python
>>> from proteus import RESTClient
>>> help(RESTClient)
```

You can also just use the CLI scripts interactively (use -h, --help)

```bash
proteus --help

    usage: Bluecat Proteus CLI Tool [-h] {static,dhcp,search} ...

    optional arguments:
      -h, --help            show this help message and exit

    Subcommands:
      {static,dhcp,search}  subparsers command help
        static              static IP record manipulation
        dhcp                dhcp IP record manipulation
        search              search Proteus for Objects

# Create a DHCP reservation
proteus dhcp create <hostname> <mac> --network <networkAddress> --creds /location/of/creds.json

# Delete a STATIC IP reservation
proteus static delete <ipAddress>
```

