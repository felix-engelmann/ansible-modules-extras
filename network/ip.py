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

import ipaddress
from ansible.module_utils.pycompat24 import get_exception

def l_key(l,key):
    elems=list(filter(lambda x: x[0] == key,l))
    if len(elems) == 0:
        return None
    else:
        return elems[0][1]

def parse_ip(text):
    addr=None
    try:
        addr = ipaddress.IPv6Interface(text)
    except ipaddress.AddressValueError:
        try:
            addr = ipaddress.IPv4Interface(text)
        except Exception:
            e = get_exception()
            raise e
    except Exception:
        e = get_exception()
        raise e
        
    return(addr)

def main():
    
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
    
    try:
        from pyroute2 import IPRoute
        from pyroute2.netlink.exceptions import NetlinkError
        from pyroute2.netlink import AF_INET6, AF_INET
    except:
        module.fail_json(msg='pyroute2 not installed')
    
    ip = IPRoute()
    
    params = module.params
    
    if params['mode'] == 'link':
        
        #special treatment, as port is not an interface
        if params['kind'] == 'port':
            module.fail_json(msg='port not yet implemented')
        
        devids=ip.link_lookup(ifname=params['dev'])
        
        if params['state']=='absent':
            if len(devids) == 1 :
                try:
                    ip.link("del",index=devids[0])
                    module.exit_json(changed=True)
                except NetlinkError:
                    e = get_exception()
                    try:
                        #HW IFs not deletable, try to bring it down
                        if l_key(ip.link("get", index=devids[0])[0]['attrs'],'IFLA_OPERSTATE') == 'DOWN':
                            module.exit_json(changed=False)
                        else:
                            ip.link("set", index=devids[0], state="down")
                            module.exit_json(changed=True)
                    except Exception:
                        e = get_exception()
                        module.fail_json(msg='could not delete or DOWN interface: '+str(e))
            else:
                module.exit_json(changed=False)
        
        
        if params['kind'] == None:
            module.fail_json(msg='ifup not yet implemented')
            pass
        elif params['kind'] == 'bridge':
            if len(devids) > 0:
                #IF exists check if for correct kind
                ifinfo=ip.link("get", index=devids[0])[0]['attrs']
                linfo = l_key(ifinfo,'IFLA_LINKINFO')
                if linfo:
                    lkind=l_key(linfo['attrs'],'IFLA_INFO_KIND')
                    if lkind != 'bridge':
                        module.fail_json(msg='interface exists already but is not a bridge')
                    else:
                        # state is implicitly given by members
                        module.exit_json(changed=False)
                else:
                    #no LINKINFO given - probably 
                    module.fail_json(msg='interface exists already but is not a bridge')
            else:
                #create bridge
                try:
                    ip.link("add",ifname=params['dev'],kind="bridge")
                    module.exit_json(changed=True)
                except Exception:
                    e = get_exception()
                    module.fail_json(msg='could not create bridge: '+str(e))
        
        elif params['kind'] == 'vlan':
            module.fail_json(msg='vlan not yet implemented')
        elif params['kind'] == 'veth':
            module.fail_json(msg='veth not yet implemented')
        
    try:
        setto=parse_ip(u''+params['addr'])
    except Exception:
        e = get_exception()
        module.fail_json(msg='invalid address: '+str(e))
    
    devids = ip.link_lookup(ifname=params['dev'])

    if len(devids) != 1:
        module.fail_json(msg='device does not exist')
    devid=devids[0]
    
    if params['mode'] == 'address':
    
        devaddrs = ip.get_addr(index=devid)
        
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
                    
        except NetlinkError:
            e = get_exception()
            module.fail_json(msg='could not perform operation: '+str(e))
            
        module.exit_json( changed=changed)
        
    elif params['mode'] == 'route':
        
        if type(setto) == ipaddress.IPv4Interface:
            family = AF_INET
        else:
            family = AF_INET6
        
        routes=ip.get_routes(family=family)
        
        via=None
        if params['via'] != None:
            try:
                via=parse_ip(u''+params['via'])
            except Exception:
                e = get_exception()
                module.fail_json(msg='invalid via address: '+str(e))
        
        present=False
        for route in routes:
            oif=list(filter(lambda x: x[0] == 'RTA_OIF' , route["attrs"]))[0][1]
            gws=list(filter(lambda x: x[0] == 'RTA_GATEWAY' , route["attrs"]))
            gw=None
            if len(gws) == 1:
                gw=parse_ip(u''+gws[0][1])
                
            prefixlen = route['dst_len']
            
            dsts=list(filter(lambda x: x[0] == 'RTA_DST' , route["attrs"]))
            if len(dsts) == 1:
                dst=parse_ip(u''+dsts[0][1]+'/'+str(prefixlen))
            else:
                if family == AF_INET:
                    dst=ipaddress.IPv4Interface(u'0.0.0.0/'+str(prefixlen))
                else:
                    dst=ipaddress.IPv6Interface(u'::/'+str(prefixlen))
            
            #print("set %s == %s" %(str(setto.network),str(dst.network)))
            
            if setto.network == dst.network and oif == devid:
                if params['state']=='absent':
                    try:
                        ip.route('delete',dst=str(dst.network),oif=oif)
                    except NetlinkError:
                        e = get_exception()
                        module.fail_json(msg='could not delete route: '+str(e))
                    
                    module.exit_json(changed=True)
                if via == None:
                    present=True
                    break
                elif gw.ip == via.ip:
                    present=True
                    break
                     
        
        if not present and params['state']=='present':
            try:
                if via == None:
                    ip.route('add', dst=str(setto.network), oif=devid)
                else:
                    ip.route('add', dst=str(setto.network), gateway=str(via.ip), oif=devid)
            except NetlinkError:
                e = get_exception()
                module.fail_json(msg='could not add route: '+str(e))
                
            module.exit_json(changed=True)
        
        module.exit_json(changed=False)
        


# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()