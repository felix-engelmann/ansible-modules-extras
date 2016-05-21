#!/usr/bin/python
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: ip
version_added: 0.1
author: "Felix Engelmann (@felix-engelmann)"
short_description: Wrapper of the linux ip tool
requirements: [ pyroute2 ]
description:
    - Performs linux ip address manipulations for interfaces and route adjustments
options:
    mode:
        required: true
        choices: [ address, route ]
        description:
            - Whether to change an address or a route
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the address should be assigned to the interface or removed
              respectively whether the route should be set or removed
    addr:
        required: false
        description:
            - The address to set or remove with prefix length (e.g. 2001:db8::2/64, 10.0.0.2/24, 10.0.0.2/255.255.255.0)
    dev:
        required: false
        description:
            - The device to set or remove the address from.
'''

EXAMPLES = '''
# set address 2001:db8::42/64 to interface eth0
- ip: mode=address addr=2001:db8::42/64 dev=eth0 state=present

# change prefix length (watch out that any other assignments of same address with different prefix will be deleted)
- ip: mode=address addr=2001:db8::42/112 dev=eth0 state=present

# remove address from interface eth0
- ip: mode=address addr=2001:db8::42/112 dev=eth0 state=absent

'''


from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import ipaddress

def parse_ip(text):
    addr=None
    try:
        addr = ipaddress.IPv6Interface(text)
    except ipaddress.AddressValueError:
        try:
            addr = ipaddress.IPv4Interface(text)
        except Exception as e:
            raise Exception(e)
    except Exception as e:
        raise Exception(e)
        
    return(addr)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            mode  = dict(choices=['address','route'], default=None, required=True),
            state = dict(choices=['present','absent'], default='present'),
            addr  = dict(default=None),
            dev   = dict(default=None),
        ),
    )
    
    ip = IPRoute()
    
    params = module.params
    
    if params['mode'] == 'address':
        
        if params['addr'] == None or params['dev'] == None:
            module.fail_json(msg='addr and dev are mandator parameters')
    
        devids = ip.link_lookup(ifname=params['dev'])
    
        if len(devids) != 1:
            module.fail_json(dev=params['dev'],msg='device does not exist')
        devid=devids[0]
    
        devaddrs = ip.get_addr(index=devid)
        
        try:
            setto=parse_ip(u''+params['addr'])
        except Exception as e:
            module.fail_json(addr=params['addr'],msg='invalid address: '+str(e))
        
        ifaddrs = []
        for ad in devaddrs:
            ifip=list(filter(lambda x: x[0] == 'IFA_ADDRESS' , ad["attrs"]))[0][1]
            prefix=ad['prefixlen']
            
            ipobj = parse_ip(u''+ifip+"/"+str(prefix))
            if ipobj:
                ifaddrs.append(ipobj)
            
        changed=False
        
        try:
            if params["state"] == 'present':
                if setto not in ifaddrs:
                    ip.addr('add', index=devid, address=setto.ip.compressed, prefixlen=setto.network.prefixlen)
                    changed=True
            
                #clean up possible same addresses with different netmasks
                for ad in filter(lambda x: x != setto and x.ip == setto.ip, ifaddrs):
                    ip.addr('delete', index=devid, address=ad.ip.compressed, prefixlen=ad.network.prefixlen)
                    changed=True
            elif params["state"] == 'absent':
                if setto in ifaddrs:
                    ip.addr('delete', index=devid, address=setto.ip.compressed, prefixlen=setto.network.prefixlen)
                    changed=True
                    
        except NetlinkError as e:
            module.fail_json(addr=params['addr'],msg='could not perform operation: '+str(e))
            
        module.exit_json(addr=setto.ip.compressed,prefixlen=setto.network.prefixlen, changed=changed)
        
    elif params['mode'] == 'route':
        module.fail_json(msg='Not yet implemented')
    


# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()