#!/usr/bin/python

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
            prefixlen  = dict(default=None, type='int'),
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