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
version_added: 2.2
author: "Felix Engelmann (@felix-engelmann)"
short_description: Wrapper of the linux ip tool
requirements: [ pyroute2 ]
description:
    - Performs linux ip address manipulations for interfaces and route adjustments.
options:
    mode:
        required: true
        choices: [ address, route, link ]
        description:
            - Whether to change an address, route or interface.
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the address should be assigned to the interface or removed
              respectively whether the route should be set or removed.
              or the interface should be brought up or down
    addr:
        required: false
        aliases: [ net ]
        description:
            - The address to set or remove with prefix length. (e.g. 2001:db8::2/64, 10.0.0.2/24, 10.0.0.2/255.255.255.0)
              For nets the default route is specified by 0.0.0.0/0 or ::/0 .
    dev:
        required: true
        description:
            - The device to set or remove the address/route from. Or the name of the new link.
    via:
        required: false
        description:
            - IP address of gateway for manipulating routes.
    kind:
        required: false
        choices: [ bridge, vlan, veth, port ]
        description:
            - Type of link to create or to set/remove interface as port of bridge.
    link:
        required: false
        aliases: [ peer, master ]
        description:
            - The interface name of the parent link for vlan or second peer for veth interfaces.
    vlan_id:
        required: false
        description:
            - The vlan ID for vlan interfaces.
'''

EXAMPLES = '''
# set address 2001:db8::42/64 to interface eth0
- ip: mode=address addr=2001:db8::42/64 dev=eth0 state=present

# change prefix length (watch out that any other assignments of same address with different prefix will be deleted)
- ip: mode=address addr=2001:db8::42/112 dev=eth0 state=present

# remove address from interface eth0
- ip: mode=address addr=2001:db8::42/112 dev=eth0 state=absent

# add route for net 2001:db3::/48 via fe80::3123 through interface eth0
- ip: mode=route net=2001:db3::/48 via=fe80::3123 dev=eth0

# add IPv4 default route through gateway 192.168.0.1 at eth0
- ip: mode=route net=0.0.0.0/0 via=192.168.0.1 dev=eth0

# remove IPv6 default route at interface eth0
- ip: mode=route net=::/0 dev=eth0 state=absent

# create bridge br0
- ip: mode=link dev=br0 kind=bridge

# add eth0 to bridge br0
- ip: mode=link dev=eth0 kind=port master=br0

# remove eth0 from bridge
- ip: mode=link dev=eth0 kind=port state=absent

# create a veth interface pair of v1p0 and v1p1
- ip: mode=link dev=v1p0 kind=veth peer=v1p1

# add vlan interface with id 42 onto eth0
- ip: mode=link dev=v100 kind=vlan link=eth0 vlan_id=42

# delete interface br0
- ip: mode=link dev=br0 state=absent 

# bring up existing interface
- ip: mode=link dev=eth1 

# bring down pyhsical interface
- ip: mode=link dev=eth1 state=absent 

'''

RETURN = '''
---
'''

from ansible.module_utils.pycompat24 import get_exception

try:
    from pyroute2 import IPRoute
    from pyroute2.netlink.exceptions import NetlinkError
    from pyroute2.netlink import AF_INET6, AF_INET
    import ipaddress
    HAS_PYROUTE=1
except ImportError:
    HAS_PYROUTE=0

ip=None

def l_key(l,key):
    elems=list(filter(lambda x: x[0] == key,l))
    if len(elems) == 0:
        return None
    else:
        return elems[0][1]

def parse_ip(text):
    addr=None
    if text:
        try:
            # is it an IPv6
            addr = ipaddress.IPv6Interface(u''+text)
        except ipaddress.AddressValueError:
            try:
                # fall back to parse it as IPv4
                addr = ipaddress.IPv4Interface(u''+text)
            except Exception:
                e = get_exception()
                module.fail_json(msg='can not parse ip %s : %s'%(text,str(e)))
        except Exception:
            e = get_exception()
            module.fail_json(msg='can not parse ip %s : %s'%(text,str(e)))
    return(addr)

#object to hold all important information of a device
class Device(object):
    
    def __init__(self,name,devid,addresses,state,master,kind,vlanid):
        self.name=name
        self.id=devid
        self.addresses=addresses
        self.state=state
        self.master=master
        self.kind=kind
        self.vlanid=vlanid
        
    def is_bridge(self):
        return self.kind=='bridge'
    
    # check if addr is assigned to this IF. Prefix has to match.
    def has_address(self, addr):
        return addr in self.addresses
    
    # check if ip is assiged. Prefixes can differ.
    def get_addr_diff_lens(self, addr):
        return [x for x in self.addresses if x.ip == addr.ip and x.network != addr.network]
        
    # adds address to interface
    def add_addr(self, addr):
        try:
            ip.addr('add', index=self.id, address=addr.ip.compressed, prefixlen=addr.network.prefixlen)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not add address %s to device %s: %s'%(addr.ip.compressed,self.name,str(e)) )
    
    def del_addr(self, addr):
        try:
            ip.addr('delete', index=self.id, address=addr.ip.compressed, prefixlen=addr.network.prefixlen)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not delete address %s from device %s: %s'%(addr.ip.compressed,self.name,str(e)) )
            
    @staticmethod
    def factoryDeviceFromName(ifname):
        devids = ip.link_lookup(ifname=ifname)
        if len(devids) != 1:
            return None
        else:
            # fetch address related information
            devaddrs = ip.get_addr(index=devids[0])
            
            addrs=[]
            
            for addr in devaddrs:
                ifip = l_key(addr['attrs'],'IFA_ADDRESS')
                prefixlen = addr['prefixlen']
                
                addrobj = parse_ip(ifip+"/"+str(prefixlen))
                if addrobj:
                    addrs.append(addrobj)
        
            # fetch link related information
            link = ip.get_links(devids[0])[0]['attrs']
            
            linkstate  = l_key(link,'IFLA_OPERSTATE')
            linkmaster = l_key(link,'IFLA_MASTER')
            
            linkinfo = l_key(link,'IFLA_LINKINFO')
            linkkind = 'system'
            vlanid = None
            if linkinfo:
                linkkind=l_key(linkinfo['attrs'],'IFLA_INFO_KIND')
                if linkkind == 'vlan':
                    infodata = l_key(linkinfo['attrs'],'IFLA_INFO_DATA')['attrs']
                    vlanid = l_key(infodata,'IFLA_VLAN_ID')
            
             
            return Device(ifname,devids[0],addrs,linkstate,linkmaster,linkkind,vlanid)
            
    def dump(self):
        print("if: %s (%d) %s"%(self.name,self.id,self.state))
        for a in self.addresses:
            print(" - %s/%d"%(a.ip.compressed,a.network.prefixlen))

def main():
    # new Ansible module
    module = AnsibleModule(
        argument_spec = dict(
            mode  = dict(choices=['address','route','link'], default=None, required=True),
            state = dict(choices=['present','absent'], default='present'),
            addr  = dict(default=None,aliases=['net']),
            dev   = dict(default=None,required=True),
            via   = dict(default=None),
            kind  = dict(choices=['bridge','vlan','veth','port'],default=None),
            link  = dict(default=None,aliases=['peer','master']),
            vlan_id= dict(default=None,type='int'),
        ),
    )
    
    # this module can not work without pyroute2 and needs ipaddress for IP manipulations
    # ipaddress is shipped with python
    
    if not HAS_PYROUTE:
        module.fail_json(msg='pyroute2 is not installed')
    
    global ip    
    ip = IPRoute()
    
    # parameters and their processing
    params  = module.params
    mode    = params['mode']
    state   = params['state']
    addr    = parse_ip(params['addr'])
    dev     = Device.factoryDeviceFromName(params['dev'])
    via     = parse_ip(params['via'])
    kind    = params['kind']
    link    = Device.factoryDeviceFromName(params['dev'])
    vlan_id = params['vlan_id']
     
    # separate different modes
    if mode == 'address':
        # check for required arguments
        if not (dev and addr):    
            module.fail_json(msg='valid device and address required')
        
        if dev.has_address(addr):
            if state == "present":
                module.exit_json(changed=False)
            else:
                dev.del_addr(addr)
                module.exit_json(changed=True)
        else:
            if state == "present":
                dev.add_addr(addr)
                # clean up possible equal addresses with different prefix length
                for badaddr in dev.get_addr_diff_lens(addr):
                    dev.del_addr(badaddr)
                
                module.exit_json(changed=True)
            else:
                changed=False
                # delete all prefixes with of this ip
                for badaddr in dev.get_addr_diff_lens(addr):
                    dev.del_addr(badaddr)
                    changed=True
                
                module.exit_json(changed=changed)
        
    elif mode == 'route':
        module.fail_json(msg='Not yet implemented')
    elif mode == 'link':
        module.fail_json(msg='Not yet implemented')
    
# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()