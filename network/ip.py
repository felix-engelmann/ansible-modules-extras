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
              For nets, the default route is specified by v4default or v6default .
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
- ip: mode=route net=v4default via=192.168.0.1 dev=eth0

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
module=None

def l_key(l,key):
    elems=list(filter(lambda x: x[0] == key,l))
    if len(elems) == 0:
        return None
    else:
        return elems[0][1]

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
            vlanid = None
            if linkinfo:
                linkkind=l_key(linkinfo['attrs'],'IFLA_INFO_KIND')
                if linkkind == 'vlan':
                    infodata = l_key(linkinfo['attrs'],'IFLA_INFO_DATA')['attrs']
                    vlanid = l_key(infodata,'IFLA_VLAN_ID')
            
             
            return Device(ifname,devids[0],addrs,linkstate,linkmaster,linkkind,vlanid)
            
    # factory to create new bridge
    @staticmethod
    def factoryCreateBridge(ifname):
        try:
            ip.link("add",ifname=ifname,kind="bridge")
        except Exception:
            e = get_exception()
            module.fail_json(msg='could not create bridge %s: %s'%(ifname,str(e)))
        
        return Device.factoryDeviceFromName(ifname)
    
    def dump(self):
        print("if: %s (%d) %s"%(self.name,self.id,self.state))
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
                rif   = l_key(route['attrs'],'RTA_OIF')
                rgw   = l_key(route['attrs'],'RTA_GATEWAY')
                rvia = None
                if rgw:
                    rvia = parse_ip(rgw)
                rdst  = l_key(route['attrs'],'RTA_DST')
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
    params    = module.params
    mode      = params['mode']
    state     = params['state']
    addr      = parse_ip(params['addr'])
    dev       = Device.factoryDeviceFromName(params['dev'])
    dev_name  = params['dev']
    via       = parse_ip(params['via'])
    kind      = params['kind']
    link      = Device.factoryDeviceFromName(params['link'])
    link_name = params['link']
    vlan_id   = params['vlan_id']
     
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
        if not (dev and addr):    
            module.fail_json(msg='valid device and network required')
            
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
                
    elif mode == 'link':
        
        # add an IF to a bridge
        if kind == 'port':
            
            if state=="present":
                if not (dev and link):    
                    module.fail_json(msg='valid device and bridge required')
                if not link.is_bridge():
                    module.fail_json(msg='bridge is not a bridge')
                    
                if dev.master == link.id:
                    module.exit_json(changed=False)
                else:
                    dev.set_master(link)
                    module.exit_json(changed=True)
            if state=="absent":
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
                    
            
        #else up or down/delete interface
        else:
        
            module.fail_json(msg='Not yet implemented')
    
# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()