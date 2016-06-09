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
module: ip_addr
version_added: 2.2
author: "Felix Engelmann (@felix-engelmann)"
short_description: Changing addresses of network interfaces
requirements: [ pyroute2 ]
description:
    - Performs linux ip address manipulations for interfaces.
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the address should be assigned to the interface or removed
    addr:
        required: false
        description:
            - The address to set or remove with prefix length. (e.g. 2001:db8::2/64, 10.0.0.2/24, 10.0.0.2/255.255.255.0)
    dev:
        required: true
        description:
            - The interface to set or remove the address from.
'''

EXAMPLES = '''
# set address 2001:db8::42/64 to interface eth0
- ip: mode=address addr=2001:db8::42/64 dev=eth0 state=present

# change prefix length (watch out that any other assignments of same address with different prefix will be deleted)
- ip: mode=address addr=2001:db8::42/112 dev=eth0 state=present

# remove address from interface eth0
- ip: mode=address addr=2001:db8::42/112 dev=eth0 state=absent

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
module=None

def parse_ip(text):
    addr=None
    if text:
        if text == 'v4default':
            addr=ipaddress.IPv4Interface(u'0.0.0.0/0')
        elif text == 'v6default':
            addr=ipaddress.IPv6Interface(u'::/0')
        else:
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
                module.fail_json(msg='can not parse ip %s: %s'%(text,str(e)))
    return(addr)

#object to hold all important information of a device
class Device(object):
    
    def __init__(self,name,devid,addresses,state,master,kind,vlanid,link):
        self.name=name
        self.id=devid
        self.addresses=addresses
        self.state=state
        self.master=master
        self.kind=kind
        self.vlanid=vlanid
        self.link=link
        
    def is_bridge(self):
        return self.kind == 'bridge'
        
    def is_vlan(self,vlan_id,link):
        return ( self.kind == 'vlan' and self.vlanid == vlan_id and self.link == link.id )
        
    def is_veth(self):
        return self.kind == 'veth'
    
    def is_up(self):
        return self.state == 'UP'
    
    # check if addr is assigned to this IF. Prefix has to match.
    def has_address(self, addr):
        return addr in self.addresses
    
    # check if ip is assiged. Prefixes can differ.
    def get_addr_diff_lens(self, addr):
        return [x for x in self.addresses if x.ip == addr.ip and x.network != addr.network]
        
    # adds address to interface (not reflected in local data)
    def add_addr(self, addr):
        try:
            ip.addr('add', index=self.id, address=addr.ip.compressed, prefixlen=addr.network.prefixlen)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not add address %s to device %s: %s'%(addr.ip.compressed,self.name,str(e)) )
    
    # deletes address from interface (not reflected in local data)
    def del_addr(self, addr):
        try:
            ip.addr('delete', index=self.id, address=addr.ip.compressed, prefixlen=addr.network.prefixlen)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not delete address %s from device %s: %s'%(addr.ip.compressed,self.name,str(e)) )
    
    
    def set_master(self,master):
        try:
            ip.link("set", index=self.id, master=master.id)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not add device %s to bridge %s: %s'%(self.name,master.name,str(e)) )
            
    def set_up(self):
        try:
            ip.link("set", index=self.id, state="up")
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not up device %s: %s'%(self.name,str(e)) )
    
    def del_master(self):
        try:
            ip.link("set", index=self.id, master=0)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not remove device %s from bridge: %s'%(self.name,str(e)) )
    
    def delete(self):
        try:
            if self.kind:
                ip.link("del",index=self.id)
            else:
                # system interface
                ip.link("set", index=self.id, state="down")      
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not delete or down device %s: %s'%(self.name,str(e)) )
    
    # factory device from device name
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
                ifip = addr.get_attr('IFA_ADDRESS')
                prefixlen = addr['prefixlen']
                
                addrobj = parse_ip(ifip+"/"+str(prefixlen))
                if addrobj:
                    addrs.append(addrobj)
        
            # fetch link related information
            link = ip.get_links(devids[0])[0]
            
            linkstate  = link.get_attr('IFLA_OPERSTATE')
            linkmaster = link.get_attr('IFLA_MASTER')
            linklink   = link.get_attr('IFLA_LINK')
            
            linkkind=None
            linkinfo = link.get_attr('IFLA_LINKINFO')
            vlanid = None
            if linkinfo:
                linkkind=linkinfo.get_attr('IFLA_INFO_KIND')
                if linkkind == 'vlan':
                    infodata = linkinfo.get_attr('IFLA_INFO_DATA')
                    vlanid = infodata.get_attr('IFLA_VLAN_ID')
            
             
            return Device(ifname,devids[0],addrs,linkstate,linkmaster,linkkind,vlanid,linklink)
            
    # factory to create new bridge
    @staticmethod
    def factoryCreateBridge(ifname):
        try:
            ip.link("add",ifname=ifname,kind="bridge")
        except Exception:
            e = get_exception()
            module.fail_json(msg='could not create bridge %s: %s'%(ifname,str(e)))
        
        return Device.factoryDeviceFromName(ifname)
        
    # factory to create new vLan
    @staticmethod
    def factoryCreateVLAN(ifname,vlan_id,link):
        try:
            ip.link("add",ifname=ifname,kind="vlan",vlan_id=vlan_id,link=link.id)
        except Exception:
            e = get_exception()
            module.fail_json(msg='could not create vlan %s tag %d on device %s: %s'%(ifname,vlan_id,link.name,str(e)))
        
        return Device.factoryDeviceFromName(ifname)
    
    @staticmethod
    def factoryCreateVeth(ifname,peer):
        try:
            if peer:
                ip.link("add",ifname=ifname,kind="veth",peer=peer)
            else:
                ip.link("add",ifname=ifname,kind="veth")
        except Exception:
            e = get_exception()
            module.fail_json(msg='could not create veth %s peer %d: %s'%(ifname,peer,str(e)))
        
        return Device.factoryDeviceFromName(ifname)
    
    def dump(self):
        print("if: %s (%d) %s"%(self.name,self.id,self.state))
        if self.vlanid:
            print(" vlan: %d"%(self.vlanid,))
        for a in self.addresses:
            print(" - %s/%d"%(a.ip.compressed,a.network.prefixlen))
    
def main():
    # new Ansible module
    global module
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(choices=['present','absent'], default='present'),
            addr  = dict(default=None),
            dev   = dict(default=None,required=True),
            ),
    )
    
    # this module can not work without pyroute2 and needs ipaddress for IP manipulations
    # ipaddress is shipped with python
    
    if not HAS_PYROUTE:
        module.fail_json(msg='pyroute2 is not installed')
    
    global ip    
    ip = IPRoute()
    
    # parameters and their processing
    params    = module.params
    state     = params['state']
    addr      = parse_ip(params['addr'])
    dev       = Device.factoryDeviceFromName(params['dev'])
    dev_name  = params['dev']
     
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
                
# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()