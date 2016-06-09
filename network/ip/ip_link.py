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
module: ip_link
version_added: 2.2
author: "Felix Engelmann (@felix-engelmann)"
short_description: Change the physical layer interface properties
requirements: [ pyroute2 ]
description:
    - Performs linux ip link manipulations for interfaces as well as creating and managing virtual interfaces (VLAN, bridge, ...).
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the interface should be brought up or down
    dev:
        required: true
        description:
            - The interface to bring up/down or the name of the new link.
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
    params    = module.params
    state     = params['state']
    dev       = Device.factoryDeviceFromName(params['dev'])
    dev_name  = params['dev']
    via       = parse_ip(params['via'])
    kind      = params['kind']
    link      = Device.factoryDeviceFromName(params['link'])
    link_name = params['link']
    vlan_id   = params['vlan_id']
        
    # add an IF to a bridge
    if kind == 'port':
        
        if state == "present":
            if not (dev and link):    
                module.fail_json(msg='valid device and bridge required')
            if not link.is_bridge():
                module.fail_json(msg='bridge is not a bridge')
                
            if dev.master == link.id:
                module.exit_json(changed=False)
            else:
                dev.set_master(link)
                module.exit_json(changed=True)
        if state == "absent":
            if not (dev):    
                module.fail_json(msg='valid device required')
                
            if dev.master == None:
                module.exit_json(changed=False)
            else:
                dev.del_master()
                module.exit_json(changed=True)
    
    # create bridge
    elif kind == 'bridge':
        
        if dev:
            if dev.is_bridge():
                if state == "present":
                    module.exit_json(changed=False)
                else:
                    dev.delete()
                    module.exit_json(changed=True)
            else:
                module.fail_json(msg='device %s exists but is not a bridge'%(dev.name,))
        else:
            if state == "absent":
                module.exit_json(changed=False)
            else:
                Device.factoryCreateBridge(dev_name)
                module.exit_json(changed=True)
    
    elif kind == 'vlan':
        
        if state == "present" and not (link and vlan_id):    
            module.fail_json(msg='valid parent device and tag required')
        
        if dev:
            if dev.is_vlan(vlan_id,link):
                if state == "present":
                    module.exit_json(changed=False)
                else:
                    dev.delete()
                    module.exit_json(changed=True)
            else:
                module.fail_json(msg='existing device %s does not match'%(dev.name,))
        else:
            if state == "present":
                Device.factoryCreateVLAN(dev_name,vlan_id,link)
                module.exit_json(changed=True)
            else:
                module.exit_json(changed=False)
    
    elif kind == 'veth':
        # there is no mean to check which is the peer interface.
        
        if link:
            if not link.is_veth():
                module.fail_json(msg='existing peer device %s is no veth'%(link.name,))
                
        if dev:
            if dev.is_veth():
                if state == "present":
                    module.exit_json(changed=False)
                else:
                    dev.delete()
                    module.exit_json(changed=True)
            else:
                module.fail_json(msg='existing device %s is no veth'%(dev.name,))
        else:
            if state == "present":
                Device.factoryCreateVeth(dev_name,link_name)
                module.exit_json(changed=True)
            else:
                module.exit_json(changed=False)
    
    #else up or down/delete interface
    else:
        
        if state == "present":
            if dev:
                if dev.is_up():
                    module.exit_json(changed=False)
                else:
                    dev.set_up()
                    module.exit_json(changed=True)
            else:
                module.fail_json(msg='could not bring up %s, device does not exist'%(dev_name,))
        else:
            if dev:
                if dev.kind:
                    # we can delete non system devices
                    dev.delete()
                    module.exit_json(changed=True)
                else:
                    if dev.is_up():
                        dev.delete()
                        module.exit_json(changed=True)
                    else:
                        module.exit_json(changed=False)
            else:
                module.exit_json(changed=False)
            
# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()