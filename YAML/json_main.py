import meraki
import yaml
import json
import os
import traceback


# Dashboard API key
api_key = "62aaae34aa0cb4aa54526cd72230c0a1b1a40ddf"
dashboard = meraki.DashboardAPI(api_key, caller="PyCharm/2023.3 JetBrains")

# Get the organizations that the user has privileges on
org = dashboard.organizations.getOrganizations()
org_id = org[0]['id']


# Make a dictionary of the file content
def file_to_dict(file):
    _, file_extension = os.path.splitext(file)   # Get the file extension
    if file_extension.lower() == '.json':   # Is file extension json or yaml
        return json_to_dict(file)
    elif file_extension.lower() == '.yaml':
        return yaml_to_dict(file)
    else:
        return 'Unknown'


# Create a dictionary of a json file
def json_to_dict(file):
    with open(file, 'r') as netfile:
        return json.load(netfile)


# Create a dictionary of a yaml file
def yaml_to_dict(file):
    with open(file, 'r') as netfile:
        return yaml.safe_load(netfile)


def get_network_ids():
    nets = {}
    for network in dashboard.organizations.getOrganizationNetworks(org_id):
        nets[network['name']] = network['id']
    return nets


# Create network in an organization
def create_network(file):
    net_dic = file_to_dict(file)
    nets = net_dic['networks']
    created_nets = []
    for network in nets:
        created_nets.append(
            dashboard.organizations.createOrganizationNetwork(
                org_id,
                **network
            )
        )
    return created_nets


# Claim device(s) into a network
def claim_device(file):
    device_dic = file_to_dict(file)
    devices = device_dic['devices']
    serials = [dev['serial'] for dev in devices]
    return dashboard.networks.claimNetworkDevices(elfa_id,serials)


# Create a new dashboard administrator
def create_admin(file):
    admin_dic = file_to_dict(file)
    user_admins = admin_dic['admins']
    admins = []
    for admin in user_admins:
        admin_data = {
            'name': admin['name'],
            'orgAccess': admin['organization_access'],
            'authenticationMethod': admin['authentication_method'],
            'email': admin['email']
        }
        if 'network_access' in admin:
            admin_data['networks'] = [{'id': networks[net], 'access': access}
                                      for net, access in admin['network_access'].items()]
        if 'tag_access' in admin:
            admin_data['tags'] = [{'tag': tag, 'access': access}
                                  for tag, access in admin['tag_access'].items()]
        admins.append(
            dashboard.organizations.createOrganizationAdmin(
                org_id,
                **admin_data
            )
        )
    return admins


# Get vlan cidr
def get_vlan_cidr(net_id, vlan):
    for vl in dashboard.appliance.getNetworkApplianceVlans(net_id):
        if vl['name'].lower() == vlan.lower():
            return vl['subnet']
    return vlan


# Enable vlans for a specific network
def enable_vlan_network(net_id):
    dashboard.appliance.updateNetworkApplianceVlansSettings(
        net_id,
        vlansEnabled=True
    )


# Create vlans for a network
def create_vlan(net_id, file):
    enable_vlan_network(net_id)
    vlan_dic = file_to_dict(file)
    vl = vlan_dic['vlans']
    vlans = []
    for vlan in vl:
        vlans.append(
            dashboard.appliance.createNetworkApplianceVlan(
                net_id,
                **vlan
            )
        )
    return vlans


# Configure management interface(s)
def mngt_interface(file):
    mngt_int_dict = file_to_dict(file)
    interfaces = mngt_int_dict['interfaces']
    mn_inter = []
    for interface in interfaces:
        mn_inter.append(
            dashboard.devices.updateDeviceManagementInterface(
                **interface
            )
        )
    return mn_inter


# Update device settings
def update_device(file):
    upd_dev_dict = file_to_dict(file)
    devs = upd_dev_dict['devices']
    devices = []
    for device in devs:
        devices.append(
            dashboard.devices.updateDevice(
                **device
            )
        )
    return devices


# Configure switch ports
def update_sw_ports(file):
    sw_port_dict = file_to_dict(file)
    ports = sw_port_dict['switchPorts']
    conf_ports = []
    for port in ports:
        conf_ports.append(
            dashboard.switch.updateDeviceSwitchPort(
                **port
            )
        )
    return conf_ports


# Update the attributes of an MR SSID
def config_ssid(net_id, file):
    ssid_dict = file_to_dict(file)
    ssids = ssid_dict['ssids']
    conf_ssid = []
    for ssid in ssids:
        conf_ssid.append(
            dashboard.wireless.updateNetworkWirelessSsid(
                net_id,
                **ssid
            )
        )
    return conf_ssid


# Update the L3 outband firewall rules of an MX network
def config_l3_out_acl(net_id, file):
    l3_acl_dict = file_to_dict(file)
    return (
        dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
            net_id,
            **l3_acl_dict
        )
    )


if __name__ == "__main__":
    try:
        create_network('network.json')
        networks = get_network_ids()
        elfa_id = networks['Elfa-exjobb']
        claim_device('deviceSettings.json')
        create_admin('admins.json')
        create_vlan(elfa_id, 'vlans.json')
        update_device('deviceSettings.json')
        update_sw_ports('swPorts.json')
        mngt_interface('mngtInterface.json')
        config_ssid(elfa_id, 'ssids.json')
        config_l3_out_acl(elfa_id, 'L3outACL.json')
        print('-' * 120)
        print("!!!THE MISSION IS ACCOMPLISHED!!!".center(120))
    except (TypeError, ValueError, KeyError, AssertionError, IndexError, FileNotFoundError) as e:
        print('-' * 120)
        print("!!!Something went WRONG!!!".center(120))
        print('-' * 120)
        print("Error:", str(e))
        traceback.print_exc()
    except Exception as e:
        print('-' * 120)
        print("!!!Something went WRONG!!!".center(120))
        print('-' * 120)
        print(f"Level:     {e.tag}\n"
              f"Operation: {e.operation}\n"
              f"Status:    {e.status} ({e.reason})\n"
              f"Errors:")
        counter = 1
        for error in e.message['errors']:
            print(f"       {counter}. {error}")
            counter += 1
    print('-' * 120)
