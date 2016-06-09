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
module: ip_route
version_added: 2.2
author: "Felix Engelmann (@felix-engelmann)"
short_description: Managing linux routes
requirements: [ pyroute2 ]
description:
    - Performs linux ip route adjustments.
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the the route should be set or removed.
    net:
        required: false
        description:
            - The net to set or remove with prefix length. (e.g. 2001:db8::2/64, 10.0.0.2/24, 10.0.0.2/255.255.255.0).
              The default route is specified by v4default or v6default .
    dev:
        required: true
        description:
            - The device to set or remove the route from. Or the name of the new link.
    via:
        required: false
        description:
            - IP address of gateway for manipulating routes.
'''

EXAMPLES = '''

# add route for net 2001:db3::/48 via fe80::3123 through interface eth0
- ip: mode=route net=2001:db3::/48 via=fe80::3123 dev=eth0

# add IPv4 default route through gateway 192.168.0.1 at eth0
- ip: mode=route net=v4default via=192.168.0.1 dev=eth0

# remove IPv6 default route at interface eth0
- ip: mode=route net=::/0 dev=eth0 state=absent

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

#object to hold all important information on a route
class Route(object):
    def __init__(self,net,interface,gateway=None):
        self.net=net
        self.interface=interface
        self.gateway=gateway
        
    def __eq__(self, other):
        if type(other) is type(self):
            return self.net == other.net and self.interface == other.interface
        return False
        
    def dump(self):
        if self.gateway:
            print("%s/%d -> %d (%s)"%(self.net.ip.compressed,self.net.network.prefixlen
                                    ,self.interface,self.gateway.ip.compressed))
        else:
            print("%s/%d -> %d"%(self.net.ip.compressed,self.net.network.prefixlen
                                    ,self.interface))
        

#object to hold all important information for routes
class Routes(object):
    
    def __init__(self,routes):
        self.routes=routes
    
    def has_route(self,dst,dev,via=None):
        for r in [x for x in self.routes if x == Route(dst,dev.id)]:
            if r.gateway == via:
                return True
        return False
    
    def has_route_any_gw(self,dst,dev):
        return Route(dst,dev.id) in self.routes
        
    def del_route(self,dst,dev):
        try:
            ip.route('delete',dst=str(dst.network),oif=dev.id)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not delete route %s via device %s: %s'%(str(dst.network),dev.name,str(e)) )
        
    def add_route(self,dst,dev,via):
        try:
            if via:
                ip.route('add',dst=str(dst.network),oif=dev.id,gateway=str(via.ip))
            else:
                ip.route('add',dst=str(dst.network),oif=dev.id)
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not add route %s via device %s and gw %s: %s'%(str(dst.network)
                                ,dev.name,str(via),str(e)) )
    
    #factory get all Routes
    @staticmethod
    def factoryRoutes():
        rs=[]
        for family in [AF_INET,AF_INET6]:
            routes=ip.get_routes(family=family)
            for route in routes:
                rif   = route.get_attr('RTA_OIF')
                rgw   = route.get_attr('RTA_GATEWAY')
                rvia = None
                if rgw:
                    rvia = parse_ip(rgw)
                rdst  = route.get_attr('RTA_DST')
                rplen = route['dst_len']
                if rplen == 0:
                    # default route
                    if family == AF_INET:
                        rdnet = parse_ip("v4default")
                    else:
                        rdnet = parse_ip("v6default")
                else:
                    rdnet = parse_ip(rdst+"/"+str(rplen))
                rs.append(Route(rdnet,rif,rvia))
        return Routes(rs)
    
    def dump(self):
        for r in self.routes:
            r.dump()
    
def main():
    # new Ansible module
    global module
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(choices=['present','absent'], default='present'),
            net   = dict(default=None),
            dev   = dict(default=None,required=True),
            via   = dict(default=None),
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
    addr      = parse_ip(params['net'])
    dev       = Device.factoryDeviceFromName(params['dev'])
    dev_name  = params['dev']
    via       = parse_ip(params['via'])
     
   
    if not (dev and addr):    
        module.fail_json(msg='valid interface and network required')
        
    routes = Routes.factoryRoutes()
    
    if state == "absent":
        if routes.has_route_any_gw(addr,dev):
            routes.del_route(addr,dev)
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)
    else:
        if routes.has_route(addr,dev,via):
            module.exit_json(changed=False)
        elif routes.has_route_any_gw(addr,dev):
            # route exists but with different gateway
            # remove it before adding new route
            routes.del_route(addr,dev)
        
        routes.add_route(addr,dev,via)
        module.exit_json(changed=True)
                
                
# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()