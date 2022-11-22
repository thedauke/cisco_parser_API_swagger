#!/usr/bin/env python
from json import encoder
from unittest import result
from cryptography.x509.ocsp import _CERT_STATUS_TO_ENUM
from netmiko import ConnectHandler
import re
import argparse
from pprint import pprint
import ipaddress
from ciscoconfparse import CiscoConfParse
from ciscoconfparse.ccp_util import CiscoRange, IPv4Obj, IPv6Obj
import pynetbox
#import time
#import sys
#import json
#command to cisco
command1 = 'show run'
command2 = 'show run | inc hostname'


#connect to cisco and get config
def get_cisco_config(command,IP):
    CONN = {
        'device_type': 'cisco_ios',
        'ip':   IP,
        'username': '',
        'password': '',
        'secret': '',
        'timeout':  20
        }
    with ConnectHandler(**CONN) as conn:
        conn.enable()
        sample_config = conn.send_command(command)
        conn.disconnect()
        return sample_config


ether_choices={
    
    'GigabitEthernet':'1000base-t',
    'FastEthernet':'100base-tx',
    'TenGigabitEthernet':'10gbase-x-sfpp',
    'mgmt':'100base-tx'
}

def parse_conf(infile,sntx):
    """Parse Cisco conf and return dict
    """
    parse = CiscoConfParse(infile, syntax=sntx, factory=True)

    int_cmds=parse.find_objects(r'^interface ')

    result={}
    result['interfaces']={}

    for interface_cmd in int_cmds:

       # get the interface name (remove the interface command from the configuration line)
        intf_name = interface_cmd.text[len("interface "):]
        result["interfaces"][intf_name] = {}

        # search for the description command, if not set use "not set" as value
        result["interfaces"][intf_name]["description"] = "not set"
        for cmd in interface_cmd.re_search_children(r"^\s+description "):
            result["interfaces"][intf_name]["description"] = cmd.text.strip()[len("description "):]

        IPv4_REGEX = r" ip\saddress\s((\d+\.\d+\.\d+\.\d+)\s(\d+\.\d+\.\d+\.\d+)|(\d+\.\d+\.\d+\.\d+)\/\S+)$"
        for cmd in interface_cmd.re_search_children(IPv4_REGEX):
            result["interfaces"][intf_name]["ip_conf"] = {}
            ipv4_addr = interface_cmd.re_match_iter_typed(IPv4_REGEX, result_type=IPv4Obj)
            result["interfaces"][intf_name]["ip_conf"].update({
                "ipv4": {
                "address": ipv4_addr.ip.exploded,
                "netmask": ipv4_addr.netmask.exploded
                }
            })
        IPv4_REGEX_S = r" ip\saddress\s((\d+\.\d+\.\d+\.\d+)\s(\d+\.\d+\.\d+\.\d+)|(\d+\.\d+\.\d+\.\d+)\/\S+)\ssecondary$"
        for cmd in interface_cmd.re_search_children(IPv4_REGEX_S):
            ipv4_addr = interface_cmd.re_match_iter_typed(IPv4_REGEX_S, result_type=IPv4Obj)
            result["interfaces"][intf_name]["ip_conf"].update({
                "secondary": {
                "address": ipv4_addr.ip.exploded,
                "netmask": ipv4_addr.netmask.exploded
                
                }
            })
        
        HSRP_REGEX = r"^ standby\s\d{1,3}\sip\s(\S+)"
        for cmd in interface_cmd.re_search_children(HSRP_REGEX):
            ipv4_addr = interface_cmd.re_match_iter_typed(HSRP_REGEX, result_type=IPv4Obj)
            result["interfaces"][intf_name]["ip_conf"].update({
                "hsrp": {
                "address": ipv4_addr.ip.exploded,
                "netmask": ipv4_addr.netmask.exploded
                }
            })

        # search for the rate_limit command, if not set use "not set" as value
        result["interfaces"][intf_name]["rate-limit"] = "not set"
        for line in interface_cmd.re_search_children(r"^\s+rate-limit input "):
            ratelimf=re.split(r"\s+",str(line))
            if 'rate-limit' in ratelimf and 'input' in ratelimf:
               idx = ratelimf.index('conform-action')
               megabytes = int(int(ratelimf[idx-2])//1.5*8//1024//1024)
               result["interfaces"][intf_name]["rate-limit"] = megabytes

        # search for the service-policy if not set use "not set" as value
        result["interfaces"][intf_name]["service-policy"] = "not set"
        for line in interface_cmd.re_search_children(r"^\s+service-policy input \d+"):
            service_sp=re.split(r"\s+",str(line))
            if 'service-policy' in service_sp and 'input' in service_sp:
               idp = service_sp.index('input')
               SPR = str(service_sp[idp+1])
               SPL = SPR.replace("'", "", 1)
               result["interfaces"][intf_name]["service-policy"] = SPL   
               
        result["interfaces"][intf_name]["is_ether"]=interface_cmd.is_ethernet_intf
        result["interfaces"][intf_name]["is_port_chan"]=interface_cmd.is_portchannel_intf
        result["interfaces"][intf_name]["is_subintf"]=interface_cmd.is_subintf
        result["interfaces"][intf_name]["port_type"]=interface_cmd.port_type
        result["interfaces"][intf_name]["ordinal_list"]=interface_cmd.ordinal_list
        if interface_cmd.has_ip_hsrp:
            result["interfaces"][intf_name]["ip_conf"].update({
                          "hsrp": {
                "address": interface_cmd.hsrp_ip_addr,
                "netmask": '255.255.255.255'
                }
            })

        if interface_cmd.intf_in_portchannel:
            result["interfaces"][intf_name]["member_of"]=interface_cmd.portchannel_number

    pprint(result)
    return result

def vlan2dict(indict):
    """Iterate over dict and return strings to import over web
    """
    vlans={}
    for intf,prop in indict["interfaces"].items():
        print(intf)
        vlannum=''
        if prop['port_type']=='Vlan' and intf!='Vlan1':
            try:
                ipv4=ipaddress.IPv4Interface(f"{prop['ip_conf']['ipv4']['address']}/{prop['ip_conf']['ipv4']['netmask']}")
            except:
                ipv4=ipaddress.IPv4Interface('127.0.0.1/32')
            vlannum=f"{prop['ordinal_list'][0]}"
            vlans[vlannum]={}
            vlans[vlannum]['net']=str(ipv4.network)
        elif prop['is_subintf']:
            try:
                ipv4=ipaddress.IPv4Interface(f"{prop['ip_conf']['ipv4']['address']}/{prop['ip_conf']['ipv4']['netmask']}")
            except:
                ipv4=ipaddress.IPv4Interface('127.0.0.1/32')
            _,vlannum=intf.split('.')
            vlans[vlannum]={}
            vlans[vlannum].update({
                   'net':str(ipv4.network)
                   })
        
        if vlannum!='' and prop['description']!='not set':
            print(vlannum)
            vlans[vlannum]['description']=prop['description'].replace('*','')
        elif vlannum!='':
            vlans[vlannum]['description']=vlannum
             
    return vlans

def vlan2import(indict):
    pprint(indict)
    for vlan,prop in indict.items():
        print(f"{args.conf_file.upper()[3:6]},{vlan},{prop['description']},Active,{prop['net']}")
        
def netbox_import_print(nb,dev_id,indict):
    """create interfaces int netbox for selected dev_id
    """
    new_intf=None
    for interface,prop in indict["interfaces"].items():
        if not prop['is_ether'] and interface!='Vlan1' or prop['is_subintf']:
            int_type='virtual'
            if prop['is_port_chan'] and not prop['is_subintf']:
                int_type='lag'
            intf_dict = {
                'name':interface,
                'form_factor':0,
                'type':int_type,
                'description':prop['description'],
                'device':dev_id,
                'custom_fields': {
                     'rate-limit': str(prop['rate-limit']), 
                     'service-policy':str(prop['service-policy'])
                     }
                
            }
            try:
                new_intf = nb.dcim.interfaces.create(intf_dict)
                if prop['is_port_chan']:
                    indict["interfaces"][interface].update({"netbox_id":new_intf.id})
            except pynetbox.RequestError as e:
                print(e.error)
            else:
                print( f"Created interface '{new_intf['name']}'")
            if prop.get('ip_conf')!=None and new_intf!=None:
                netbox_ipaddr(nb,prop,new_intf)
        elif prop['is_ether']:
            try:
                iface = nb.dcim.interfaces.get(device_id=dev_id, name=interface)
            except pynetbox.RequestError as e:
                print(e.error)
            if iface==None and not prop['is_subintf']:
                intf_dict = {
                    'name':interface,
                    'form_factor':0,
                    'type':ether_choices[prop['port_type']],
                    'description':prop['description'],
                    'device':dev_id,
                    'custom_fields': {
                        'rate-limit': str(prop['rate-limit']), 
                        'service-policy':str(prop['service-policy'])
                        }
                }
                iface = nb.dcim.interfaces.create(intf_dict)
                print( f"Created interface '{iface['name']}'")
            if prop.get('member_of')!=None:
                #If there is property with 'member_of' else update only 'description'
                pc=str(prop['member_of'])
                if args.syntax=='nxos':
                    lag_id=indict["interfaces"][f"port-channel{pc}"]["netbox_id"]
                else:
                    lag_id=indict["interfaces"][f"Port-channel{pc}"]["netbox_id"]
                patch_dict = {
                    'description':prop['description'],
                    'lag':lag_id
                }
            else:
                patch_dict = {
                    'description':prop['description'],
                }
            print(iface)
            try:
                iface.update(patch_dict)
                iface.save()
            except pynetbox.RequestError as e:
                print(e.error)
            if prop.get('ip_conf')!=None and iface!=None:
                netbox_ipaddr(nb,prop,iface)
            
def netbox_ipaddr(nb,intf_prop,intf):
    """
    Create ipaddr
    """
    for ip_conf,val in intf_prop["ip_conf"].items():
        ip_role=''
        if ip_conf=="ipv4" and intf_prop['port_type']=='Loopback':
            ip_role='loopback'
        elif ip_conf=="hsrp":
            ip_role="hsrp"
        elif ip_conf=="secondary":
            ip_role="secondary"
        ip_addr_dict = {
                    'address':f"{val['address']}/{val['netmask']}",
                    'status':"active",
                    'description':intf_prop['description'],
                    'assigned_object_type': 'dcim.interface',
                    'assigned_object_id': intf.id,
                    'assigned_object': intf.id,
                    'role':ip_role,
                    'interface': intf.id
                }
        try:
            new_ip = nb.ipam.ip_addresses.create(ip_addr_dict)
        except pynetbox.RequestError as e:
            print(e.error)
        else:
            print( f" , which has IP {new_ip['address']}."  )
            

nbconnect = pynetbox.api(
    "http://",
    #private_key_file='/path/to/private-key.pem',
    token=''
    )

parser = argparse.ArgumentParser(
    description='Parse config and import to Netbox'
    )
parser.add_argument(
    '-ip',
    dest='ip',
    help='device ip to parse'
    )
parser.add_argument(
    '-r',
    '--conf_file',
    default='./shrun.txt',
    dest='conf_file',
    type=str,
    help='config file type (default:)'
    )
parser.add_argument(
    '-o',
    '--parsed_file_path',
    default='./parsed_result.txt',
    type=str,
    help='config file type (default:)'
    )
parser.add_argument(
    '-s',
    dest='syntax',
    action='store',
    help='syntax CiscoConfParse: nxos,ios etc...',
    required=True
    )
parser.add_argument(
    '-did',
    dest='did',
    action='store',
    help='device id in Netbox',
    type=int)
parser.add_argument(
    '-p',
    action='store_true',
    help='push data to Netbox'
    )
args = parser.parse_args()


#check connection   
#mdict1= get_cisco_config ()
#D_IP = args.IP


#hostname = get_cisco_config(command2,args.ip)
#print (hostname)
sh_run = get_cisco_config(command1,args.ip)
#time.sleep(4)
open("./shrun.txt","w").close
shrun_file = open("./shrun.txt", "w")
shrun = shrun_file.write(sh_run)
shrun_file.close()

mdict=parse_conf(args.conf_file,args.syntax)
vlan2import(vlan2dict(mdict))
if args.p:
    netbox_import_print(nbconnect,args.did,mdict)
