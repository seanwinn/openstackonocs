#!/bin/bash

export CONTROLLER_HOST=127.0.0.1
export CONTROLLER_HOST_PRIV=$CONTROLLER_HOST

export DEBIAN_FRONTEND=noninteractive
# Setup Proxy

export APT_PROXY=10.0.4.18
export APT_PROXY_PORT=3142
#
# Setup the OCS OpenStack Demo proxy

if [[ ! -z "$APT_PROXY" ]]
then
	echo 'Acquire::http { Proxy "http://'${APT_PROXY}:${APT_PROXY_PORT}'"; };' | sudo tee /etc/apt/apt.conf.d/01apt-cacher-ng-proxy
fi


sudo sysctl net.ipv4.conf.all.forwarding=1

HOST_NAME=$(cat /etc/hostname)
export MY_IP=127.0.0.1
PUB_IP=$(ifconfig eth0 | awk '/inet addr/ {split ($2,A,":"); print A[2]}')
MAC_ADDR=$(ip a show eth0 | awk '/ether/ {print $2}')

echo "$PUB_IP	$HOST_NAME	$HOST_NAME" | sudo tee -a /etc/hosts

# Define environment variables to contain the OpenStack Controller Public and Private IP for later use with Cinder
export OSCONTROLLER=$MY_IP
export OSCONTROLLER_P=$OSCONTROLLER

# Icehouse cloud archive only needed with precise
#sudo apt-get -y install ubuntu-cloud-keyring
sudo apt-get update && sudo apt-get upgrade -y

# MySQL
export MYSQL_HOST=$MY_IP
export MYSQL_ROOT_PASS=openstack
export MYSQL_DB_PASS=openstack

echo "mysql-server-5.5 mysql-server/root_password password $MYSQL_ROOT_PASS" | sudo debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password_again password $MYSQL_ROOT_PASS" | sudo debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password seen true" | sudo debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password_again seen true" | sudo debconf-set-selections

###############################
# MySQL Install
###############################

sudo apt-get -y install vim mysql-server python-mysqldb

sudo sed -i "s/^bind\-address.*/bind-address = 0.0.0.0/g" /etc/mysql/my.cnf
sudo sed -i "s/^#max_connections.*/max_connections = 512/g" /etc/mysql/my.cnf

# Skip Name Resolve
echo "[mysqld]
skip-name-resolve" | sudo tee -a /etc/mysql/conf.d/skip-name-resolve.cnf

sudo restart mysql

# Ensure root can do its job
mysql -u root --password=${MYSQL_ROOT_PASS} -h localhost -e "GRANT ALL ON *.* to root@\"localhost\" IDENTIFIED BY \"${MYSQL_ROOT_PASS}\" WITH GRANT OPTION;"
mysql -u root --password=${MYSQL_ROOT_PASS} -h localhost -e "GRANT ALL ON *.* to root@\"${MYSQL_HOST}\" IDENTIFIED BY \"${MYSQL_ROOT_PASS}\" WITH GRANT OPTION;"
mysql -u root --password=${MYSQL_ROOT_PASS} -h localhost -e "GRANT ALL ON *.* to root@\"%\" IDENTIFIED BY \"${MYSQL_ROOT_PASS}\" WITH GRANT OPTION;"

mysqladmin -uroot -p${MYSQL_ROOT_PASS} flush-privileges

sudo apt-get install -y rabbitmq-server 

###############################
# Keystone Install
###############################
sudo apt-get -y install keystone python-keystoneclient

MYSQL_ROOT_PASS=openstack
MYSQL_KEYSTONE_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE keystone;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'keystone'@'%' = PASSWORD('$MYSQL_KEYSTONE_PASS');"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'keystone'@'localhost' = PASSWORD('$MYSQL_KEYSTONE_PASS');"

sudo sed -i "s#^connection.*#connection = mysql://keystone:${MYSQL_KEYSTONE_PASS}@${MYSQL_HOST}/keystone#" /etc/keystone/keystone.conf

sudo sed -i 's/^# admin_token.*/admin_token = ADMIN/' /etc/keystone/keystone.conf

sudo service keystone restart

sudo keystone-manage db_sync

export ENDPOINT=${MY_IP}
export SERVICE_TOKEN=ADMIN
export SERVICE_ENDPOINT=http://${ENDPOINT}:35357/v2.0

# admin role
keystone role-create --name admin

# Member role
keystone role-create --name Member

keystone tenant-create --name interop --description "Default interop Tenant" --enabled true

TENANT_ID=$(keystone tenant-list | awk '/\ interop\ / {print $2}')

export PASSWORD=openstack
keystone user-create --name admin --tenant_id $TENANT_ID --pass $PASSWORD --email root@localhost --enabled true

TENANT_ID=$(keystone tenant-list | awk '/\ interop\ / {print $2}')

ROLE_ID=$(keystone role-list | awk '/\ admin\ / {print $2}')

USER_ID=$(keystone user-list | awk '/\ admin\ / {print $2}')

keystone user-role-add --user $USER_ID --role $ROLE_ID --tenant_id $TENANT_ID

# Create the user
PASSWORD=openstack
keystone user-create --name demo --tenant_id $TENANT_ID --pass $PASSWORD --email demo@localhost --enabled true

TENANT_ID=$(keystone tenant-list | awk '/\ interop\ / {print $2}')

ROLE_ID=$(keystone role-list | awk '/\ Member\ / {print $2}')

USER_ID=$(keystone user-list | awk '/\ demo\ / {print $2}')

# Assign the Member role to the demo user in interop
keystone user-role-add --user $USER_ID --role $ROLE_ID --tenant_id $TENANT_ID

# Neutron Network Service Endpoint
keystone service-create --name network --type network --description 'Neutron Network Service'

# Cinder Block Storage Endpoint
keystone service-create --name volume --type volume --description 'Volume Service'

# OpenStack Compute Nova API Endpoint
keystone service-create --name nova --type compute --description 'OpenStack Compute Service'

# OpenStack Orchestration Heat API Endpoint
keystone service-create --name heat --type orchestration --description 'OpenStack Orchestration Service'

# OpenStack Compute EC2 API Endpoint
keystone service-create --name ec2 --type ec2 --description 'EC2 Service'

# OpenStack Swift Object Storage Endpoint
keystone service-create --name swift --type object-store --description 'OpenStack Object Storage Service'

# Keystone Identity Service Endpoint
keystone service-create --name keystone --type identity --description 'OpenStack Identity Service'

# Glance Image Service Endpoint
keystone service-create --name glance --type image --description 'OpenStack Image Service'

# Keystone OpenStack Identity Service
KEYSTONE_SERVICE_ID=$(keystone service-list | awk '/\ keystone\ / {print $2}')

PUBLIC="http://$PUB_IP:5000/v2.0"
ADMIN="http://$ENDPOINT:35357/v2.0"
INTERNAL="http://$ENDPOINT:5000/v2.0"

keystone endpoint-create --region regionOne --service_id $KEYSTONE_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# Glance Image Service
GLANCE_SERVICE_ID=$(keystone service-list | awk '/\ glance\ / {print $2}')

PUBLIC="http://$PUB_IP:9292"
ADMIN="http://$ENDPOINT:9292"
INTERNAL=$ADMIN

keystone endpoint-create --region regionOne --service_id $GLANCE_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# OpenStack Compute Nova API
NOVA_SERVICE_ID=$(keystone service-list | awk '/\ nova\ / {print $2}')

PUBLIC="http://$PUB_IP:8774/v2/\$(tenant_id)s"
ADMIN="http://$ENDPOINT:8774/v2/\$(tenant_id)s"
INTERNAL=$ADMIN

keystone endpoint-create --region regionOne --service_id $NOVA_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# OpenStack Compute EC2 API
EC2_SERVICE_ID=$(keystone service-list | awk '/\ ec2\ / {print $2}')

PUBLIC="http://$PUB_IP:8773/services/Cloud"
ADMIN="http://$ENDPOINT:8773/services/Admin"
INTERNAL="http://$ENDPOINT:8773/services/Cloud"

keystone endpoint-create --region regionOne --service_id $EC2_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# Cinder Block Storage Service
CINDER_SERVICE_ID=$(keystone service-list | awk '/\ volume\ / {print $2}')
CINDER_ENDPOINT=$(echo $OSCONTROLLER | sed 's/\.[0-9]*$/.211/') #Change last octet of OpenStack Controller IP to the Cinder IP.  If you changed the Cinder IP's last octet, then change the .211 in this sed command

PUBLIC="http://$PUB_IP:8776/v1/%(tenant_id)s" 
ADMIN="http://$ENDPOINT:8776/v1/%(tenant_id)s" 
INTERNAL=$ADMIN

keystone endpoint-create --region regionOne --service_id $CINDER_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# Neutron Network Service
NEUTRON_SERVICE_ID=$(keystone service-list | awk '/\ network\ / {print $2}')

PUBLIC="http://$PUB_IP:9696/"
ADMIN="http://$ENDPOINT:9696/"
INTERNAL=$ADMIN

keystone endpoint-create --region regionOne --service_id $NEUTRON_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# Heat Orchestration Service
HEAT_SERVICE_ID=$(keystone service-list | awk '/\ orchestration\ / {print $2}')

PUBLIC="http://$PUB_IP:8004/v1/%(tenant_id)s"
ADMIN="http://$ENDPOINT:8004/v1/%(tenant_id)s"
INTERNAL=$ADMIN

keystone endpoint-create --region regionOne --service_id $HEAT_SERVICE_ID --publicurl $PUBLIC --adminurl $ADMIN --internalurl $INTERNAL

# Service Tenant
keystone tenant-create --name service --description "Service Tenant" --enabled true

SERVICE_TENANT_ID=$(keystone tenant-list | awk '/\ service\ / {print $2}')
keystone user-create --name keystone --pass keystone --tenant_id $SERVICE_TENANT_ID --email keystone@localhost --enabled true

keystone user-create --name glance --pass glance --tenant_id $SERVICE_TENANT_ID --email glance@localhost --enabled true

keystone user-create --name nova --pass nova --tenant_id $SERVICE_TENANT_ID --email nova@localhost --enabled true

keystone user-create --name cinder --pass cinder --tenant_id $SERVICE_TENANT_ID --email cinder@localhost --enabled true

keystone user-create --name neutron --pass neutron --tenant_id $SERVICE_TENANT_ID --email neutron@localhost --enabled true

keystone user-create --name heat --pass heat --tenant_id $SERVICE_TENANT_ID --email heat@localhost --enabled true


# Set user ids
ADMIN_ROLE_ID=$(keystone role-list | awk '/\ admin\ / {print $2}')
KEYSTONE_USER_ID=$(keystone user-list | awk '/\ keystone\ / {print $2}')
GLANCE_USER_ID=$(keystone user-list | awk '/\ glance\ / {print $2}')
NOVA_USER_ID=$(keystone user-list | awk '/\ nova\ / {print $2}')
CINDER_USER_ID=$(keystone user-list | awk '/\ cinder \ / {print $2}')
NEUTRON_USER_ID=$(keystone user-list | awk '/\ neutron \ / {print $2}')
HEAT_USER_ID=$(keystone user-list | awk '/\ heat \ / {print $2}')

# Assign the keystone user the admin role in service tenant
keystone user-role-add --user $KEYSTONE_USER_ID --role $ADMIN_ROLE_ID --tenant_id $SERVICE_TENANT_ID

# Assign the glance user the admin role in service tenant
keystone user-role-add --user $GLANCE_USER_ID --role $ADMIN_ROLE_ID --tenant_id $SERVICE_TENANT_ID

# Assign the nova user the admin role in service tenant
keystone user-role-add --user $NOVA_USER_ID --role $ADMIN_ROLE_ID --tenant_id $SERVICE_TENANT_ID

# Assign the cinder user the admin role in service tenant
keystone user-role-add --user $CINDER_USER_ID --role $ADMIN_ROLE_ID --tenant_id $SERVICE_TENANT_ID

# Grant admin role to neutron service user
keystone user-role-add --user $NEUTRON_USER_ID --role $ADMIN_ROLE_ID --tenant_id $SERVICE_TENANT_ID

# Assign the heat user the admin role in service tenant
keystone user-role-add --user $HEAT_USER_ID --role $ADMIN_ROLE_ID --tenant_id $SERVICE_TENANT_ID

###############################
# Glance Install
###############################

# Install Service

sudo apt-get -y --force-yes install glance python-glanceclient

# Create database
MYSQL_ROOT_PASS=openstack
MYSQL_GLANCE_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE glance;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'glance'@'%' = PASSWORD('$MYSQL_GLANCE_PASS');"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'localhost';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'glance'@'localhost' = PASSWORD('$MYSQL_GLANCE_PASS');"

# glance-api.conf
echo "[keystone_authtoken]
service_protocol = http
service_host = ${MY_IP}
service_port = 5000
auth_host = ${MY_IP}
auth_port = 35357
auth_protocol = http
auth_uri = http://${MY_IP}:5000/
admin_tenant_name = service
admin_user = glance
admin_password = glance
[paste_deploy]
config_file = /etc/glance/glance-api-paste.ini
flavor = keystone
" | sudo tee -a /etc/glance/glance-api.conf

# glance-registry.conf
echo "[keystone_authtoken]
service_protocol = http
service_host = ${MY_IP}
service_port = 5000
auth_host = ${MY_IP}
auth_port = 35357
auth_protocol = http
auth_uri = http://${MY_IP}:5000/
admin_tenant_name = service
admin_user = glance
admin_password = glance
[paste_deploy]
config_file = /etc/glance/glance-registry-paste.ini
flavor = keystone
" | sudo tee -a /etc/glance/glance-registry.conf

sudo sed -i "s,^#connection.*,connection = mysql://glance:${MYSQL_GLANCE_PASS}@${MYSQL_HOST}/glance," /etc/glance/glance-registry.conf
sudo sed -i "s,^#connection.*,connection = mysql://glance:${MYSQL_GLANCE_PASS}@${MYSQL_HOST}/glance," /etc/glance/glance-api.conf

sudo stop glance-registry
sudo start glance-registry
sudo stop glance-api
sudo start glance-api
sudo glance-manage db_sync
mysql -u root -popenstack -e "use glance;alter table migrate_version convert to charset utf8;"
sudo glance-manage db_sync

# Get some images and upload
export OS_TENANT_NAME=interop
export OS_USERNAME=admin
export OS_PASSWORD=openstack
export OS_AUTH_URL=http://${MY_IP}:5000/v2.0/
export OS_NO_CACHE=1

sudo apt-get -y install wget

# Get the images
# First check host
CIRROS="cirros-0.3.0-x86_64-disk.img"
UBUNTU="trusty-server-cloudimg-amd64-disk1.img"

if [[ ! -f /home/ubuntu/${CIRROS} ]]
then
        # Download then store on local host for next time
	wget --quiet https://launchpad.net/cirros/trunk/0.3.0/+download/cirros-0.3.0-x86_64-disk.img 
fi

if [[ ! -f /home/ubuntu/${UBUNTU} ]]
then
        # Download then store on local host for next time
	wget --quiet http://uec-images.ubuntu.com/trusty/current/trusty-server-cloudimg-amd64-disk1.img       
fi

glance image-create --name='Ubuntu 14.04 x86_64 Server' --disk-format=qcow2 --container-format=bare --public --file /trusty-server-cloudimg-amd64-disk1.img
glance image-create --name='cirros-0.3.0-x86_64' --disk-format=qcow2 --container-format=bare --public --file /cirros-0.3.0-x86_64-disk.img

###############################
# Neutron Install
###############################
# Create database
MYSQL_HOST=${MY_IP}
GLANCE_HOST=${MY_IP}
KEYSTONE_ENDPOINT=${MY_IP}
CONTROLLER_HOST=${MY_IP}
SERVICE_TENANT=service
SERVICE_PASS=nova

# Create database
MYSQL_ROOT_PASS=openstack
MYSQL_NEUTRON_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE neutron;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'%';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'neutron'@'%' = PASSWORD('$MYSQL_NEUTRON_PASS');"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'localhost';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'neutron'@'localhost' = PASSWORD('$MYSQL_NEUTRON_PASS');"

sudo apt-get -y install neutron-server neutron-plugin-ml2 neutron-plugin-openvswitch-agent openvswitch-datapath-dkms  neutron-l3-agent neutron-dhcp-agent neutron-common


sudo /etc/init.d/openvswitch-switch start
sudo ovs-vsctl add-br br-int
sudo ovs-vsctl add-br br-ex
# Configuration
sudo mkdir -p /etc/neutron/backup
sudo cp -rf /etc/neutron/* /etc/neutron/backup/


# /etc/neutron/api-paste.ini
sudo rm -f /etc/neutron/api-paste.ini
echo "
[composite:neutron]
use = egg:Paste#urlmap
/: neutronversions
/v2.0: neutronapi_v2_0

[composite:neutronapi_v2_0]
use = call:neutron.auth:pipeline_factory
noauth = extensions neutronapiapp_v2_0
keystone = authtoken keystonecontext extensions neutronapiapp_v2_0

[filter:keystonecontext]
paste.filter_factory = neutron.auth:NeutronKeystoneContext.factory

[filter:authtoken]
paste.filter_factory = keystoneclient.middleware.auth_token:filter_factory
auth_host = ${CONTROLLER_HOST}
auth_port = 35357
auth_protocol = http
admin_tenant_name = service
admin_user = neutron
admin_password = neutron

[filter:extensions]
paste.filter_factory = neutron.api.extensions:plugin_aware_extension_middleware_factory

[app:neutronversions]
paste.app_factory = neutron.api.versions:Versions.factory

[app:neutronapiapp_v2_0]
paste.app_factory = neutron.api.v2.router:APIRouter.factory
" | sudo tee -a /etc/neutron/api-paste.ini

# /etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini
echo "
[DATABASE]
connection=mysql://neutron:openstack@${CONTROLLER_HOST}/neutron
[OVS]
tenant_network_type=gre
tunnel_id_ranges=1:1000
integration_bridge=br-int
tunnel_bridge=br-tun
local_ip=${PUB_IP}
enable_tunneling=True
root_helper = sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf
[SECURITYGROUP]
# Firewall driver for realizing neutron security group function
firewall_driver = quantum.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
" | sudo tee -a /etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini

# /etc/neutron/dhcp_agent.ini 
#echo "root_helper = sudo neutron-rootwrap /etc/neutron/rootwrap.conf" >> /etc/neutron/dhcp_agent.ini
echo "
root_helper = sudo
use_namespaces = True
" | sudo tee -a /etc/neutron/dhcp_agent.ini

echo "
Defaults !requiretty
neutron ALL=(ALL:ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers


# Configure Neutron
sudo sed -i "s/# rabbit_host = localhost/rabbit_host = ${CONTROLLER_HOST}/g" /etc/neutron/neutron.conf
sudo sed -i "s,rpc_backend.*,rpc_backend = neutron.openstack.common.rpc.impl_kombu," /etc/neutron/neutron.conf
sudo sed -i "s,^notify_nova_on_port_status_changes.*,notify_nova_on_port_status_changes = True," /etc/neutron/neutron.conf
sudo sed -i "s,^notify_nova_on_port_data_changes.*,notify_nova_on_port_data_changes = True," /etc/neutron/neutron.conf
sudo sed -i "s,^nova_url.*,nova_url = http://${CONTROLLER_HOST}:8774/v2," /etc/neutron/neutron.conf
sudo sed -i "s,^nova_admin_username.*,nova_admin_username = nova," /etc/neutron/neutron.conf
sudo sed -i "s,^nova_admin_tenant_id.*,nova_admin_tenant_id = ${SERVICE_TENANT_ID}," /etc/neutron/neutron.conf
sudo sed -i "s,^nova_admin_password.*,nova_admin_password = ${NOVA_PASS}," /etc/neutron/neutron.conf
sudo sed -i "s,^nova_admin_auth_url.*,nova_admin_auth_url = http://${CONTROLLER_HOST}:35357/v2.0," /etc/neutron/neutron.conf
sudo sed -i 's/# auth_strategy = keystone/auth_strategy = keystone/g' /etc/neutron/neutron.conf
sudo sed -i "s/auth_host = 127.0.0.1/auth_host = ${CONTROLLER_HOST}/g" /etc/neutron/neutron.conf
sudo sed -i 's/admin_tenant_name = %SERVICE_TENANT_NAME%/admin_tenant_name = service/g' /etc/neutron/neutron.conf
sudo sed -i 's/admin_user = %SERVICE_USER%/admin_user = neutron/g' /etc/neutron/neutron.conf
sudo sed -i 's/admin_password = %SERVICE_PASSWORD%/admin_password = neutron/g' /etc/neutron/neutron.conf
sudo sed -i 's/^root_helper.*/root_helper = sudo/g' /etc/neutron/neutron.conf
sudo sed -i 's/# allow_overlapping_ips = False/allow_overlapping_ips = True/g' /etc/neutron/neutron.conf
sudo sed -i "s,connection = sqlite:////var/lib/neutron/neutron.sqlite,connection = mysql://neutron:openstack@${CONTROLLER_HOST}/neutron," /etc/neutron/neutron.conf
sudo sed -i "s/# interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver/interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver/g" /etc/neutron/l3_agent.ini
sudo sed -i "s/# service_plugins =/service_plugins = router,lbaas/g" /etc/neutron/neutron.conf
sudo sed -i 's/^core_plugin.*/core_plugin = ml2/g' /etc/neutron/neutron.conf


# /etc/neutron/l3_agent.ini
sudo rm -rf /etc/neutron/plugins/ml2/ml2_conf.ini
echo "
[ml2]

type_drivers = gre
tenant_network_types = gre
mechanism_drivers = openvswitch

[ml2_type_gre]

tunnel_id_ranges = 1:1000

[ovs]

local_ip = ${PUB_IP}
tunnel_type = gre
enable_tunneling = True

[securitygroup]

firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
enable_security_group = True

" | sudo tee -a /etc/neutron/plugins/ml2/ml2_conf.ini



# /etc/neutron/l3_agent.ini
sudo rm -rf /etc/neutron/l3_agent.ini
echo "
[DEFAULT]
# Show debugging output in log (sets DEBUG log level output)
# debug = False

# L3 requires that an interface driver be set. Choose the one that best
# matches your plugin.
# interface_driver =

# Example of interface_driver option for OVS based plugins (OVS, Ryu, NEC)
# that supports L3 agent
interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver

# Use veth for an OVS interface or not.
# Support kernels with limited namespace support
# (e.g. RHEL 6.5) so long as ovs_use_veth is set to True.
# ovs_use_veth = False

# Example of interface_driver option for LinuxBridge
# interface_driver = neutron.agent.linux.interface.BridgeInterfaceDriver

# Allow overlapping IP (Must have kernel build with CONFIG_NET_NS=y and
# iproute2 package that supports namespaces).
use_namespaces = True

# If use_namespaces is set as False then the agent can only configure one router.

# This is done by setting the specific router_id.
# router_id =

# Each L3 agent can be associated with at most one external network.  This
# value should be set to the UUID of that external network.  If empty,
# the agent will enforce that only a single external networks exists and
# use that external network id
# gateway_external_network_id =

# Indicates that this L3 agent should also handle routers that do not have
# an external network gateway configured.  This option should be True only
# for a single agent in a Neutron deployment, and may be False for all agents
# if all routers must have an external network gateway
# handle_internal_only_routers = True

# Name of bridge used for external network traffic. This should be set to
# empty value for the linux bridge
# external_network_bridge = br-ex

# TCP Port used by Neutron metadata server
# metadata_port = 9697

# Send this many gratuitous ARPs for HA setup. Set it below or equal to 0
# to disable this feature.
# send_arp_for_ha = 3

# seconds between re-sync routers' data if needed
# periodic_interval = 40

# seconds to start to sync routers' data after
# starting agent
# periodic_fuzzy_delay = 5

# enable_metadata_proxy, which is true by default, can be set to False
# if the Nova metadata server is not available
# enable_metadata_proxy = True

# Location of Metadata Proxy UNIX domain socket
# metadata_proxy_socket = $state_path/metadata_proxy

auth_url = http://${CONTROLLER_HOST}:35357/v2.0
auth_region = regionOne
admin_tenant_name = service
admin_user = neutron
admin_password = neutron
metadata_ip = ${CONTROLLER_HOST}
metadata_port = 8775
use_namespaces = True
" | sudo tee -a /etc/neutron/l3_agent.ini

# Metadata Agent

sudo rm -rf /etc/neutron/metadata_agent.ini
echo "[DEFAULT]
# Show debugging output in log (sets DEBUG log level output)
# debug = True

# The Neutron user information for accessing the Neutron API.
auth_url = http://${CONTROLLER_HOST}:5000/v2.0
auth_region = regionOne
admin_tenant_name = service
admin_user = neutron
admin_password = neutron

# Network service endpoint type to pull from the keystone catalog
# endpoint_type = adminURL

# IP address used by Nova metadata server
nova_metadata_ip = ${CONTROLLER_HOST}

# TCP Port used by Nova metadata server
nova_metadata_port = 8775

# When proxying metadata requests, Neutron signs the Instance-ID header with a
# shared secret to prevent spoofing.  You may select any string for a secret,
# but it must match here and in the configuration used by the Nova Metadata
# Server. NOTE: Nova uses a different key: neutron_metadata_proxy_shared_secret
metadata_proxy_shared_secret = foo
" | sudo tee -a /etc/neutron/metadata_agent.ini

#DHCP Agent

sudo rm -rf /etc/neutron/dhcp_agent.ini
echo "[DEFAULT]
# Show debugging output in log (sets DEBUG log level output)
# debug = False

# The DHCP agent will resync its state with Neutron to recover from any
# transient notification or rpc errors. The interval is number of
# seconds between attempts.
# resync_interval = 5

# The DHCP agent requires an interface driver be set. Choose the one that best
# matches your plugin.
# interface_driver =

# Example of interface_driver option for OVS based plugins(OVS, Ryu, NEC, NVP,
# BigSwitch/Floodlight)
interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver

# Use veth for an OVS interface or not.
# Support kernels with limited namespace support
# (e.g. RHEL 6.5) so long as ovs_use_veth is set to True.
# ovs_use_veth = False

# Example of interface_driver option for LinuxBridge
# interface_driver = neutron.agent.linux.interface.BridgeInterfaceDriver

# The agent can use other DHCP drivers.  Dnsmasq is the simplest and requires
# no additional setup of the DHCP server.
dhcp_driver = neutron.agent.linux.dhcp.Dnsmasq

# Allow overlapping IP (Must have kernel build with CONFIG_NET_NS=y and
# iproute2 package that supports namespaces).
use_namespaces = True

# The DHCP server can assist with providing metadata support on isolated
# networks. Setting this value to True will cause the DHCP server to append
# specific host routes to the DHCP request.  The metadata service will only
# be activated when the subnet gateway_ip is None.  The guest instance must
# be configured to request host routes via DHCP (Option 121).
enable_isolated_metadata = True

# Allows for serving metadata requests coming from a dedicated metadata
# access network whose cidr is 169.254.169.254/16 (or larger prefix), and
# is connected to a Neutron router from which the VMs send metadata
# request. In this case DHCP Option 121 will not be injected in VMs, as
# they will be able to reach 169.254.169.254 through a router.
# This option requires enable_isolated_metadata = True
# enable_metadata_network = False

# Number of threads to use during sync process. Should not exceed connection
# pool size configured on server.
# num_sync_threads = 4

# Location to store DHCP server config files
# dhcp_confs = $state_path/dhcp

# Domain to use for building the hostnames
# dhcp_domain = openstacklocal

# Override the default dnsmasq settings with this file
# dnsmasq_config_file =

# Use another DNS server before any in /etc/resolv.conf.
# dnsmasq_dns_server =

# Limit number of leases to prevent a denial-of-service.
# dnsmasq_lease_max = 16777216

# Location to DHCP lease relay UNIX domain socket
# dhcp_lease_relay_socket = $state_path/dhcp/lease_relay

# Location of Metadata Proxy UNIX domain socket
# metadata_proxy_socket = $state_path/metadata_proxy

#Custom MTU value to support GRE tunneling within 1500MTU max
dnsmasq_config_file=/etc/neutron/dnsmasq-neutron.conf
" | sudo tee -a /etc/neutron/dhcp_agent.ini

echo "dhcp-option-force=26,1400" | sudo tee -a /etc/neutron/dnsmasq-neutron.conf

sudo service neutron-server restart
sudo service neutron-plugin-openvswitch-agent restart

###############################
# Nova Install
###############################

# Create database
MYSQL_HOST=${MY_IP}
GLANCE_HOST=${MY_IP}
KEYSTONE_ENDPOINT=${MY_IP}
SERVICE_TENANT=service
SERVICE_PASS=nova

MYSQL_ROOT_PASS=openstack
MYSQL_NOVA_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE nova;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%'"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'nova'@'%' = PASSWORD('$MYSQL_NOVA_PASS');"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost'"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'nova'@'localhost' = PASSWORD('$MYSQL_NOVA_PASS');"

sudo apt-get -y --force-yes install nova-api nova-cert nova-conductor nova-consoleauth nova-novncproxy nova-scheduler python-novaclient nova-compute-kvm python-guestfs
sudo dpkg-statoverride  --update --add root root 0644 /boot/vmlinuz-$(uname -r)


# Clobber the nova.conf file with the following
NOVA_CONF=/etc/nova/nova.conf
NOVA_API_PASTE=/etc/nova/api-paste.ini
sudo mkdir -p /etc/nova/backup
sudo cp -rf /etc/nova/* /etc/nova/backup/
sudo rm -rf $NOVA_CONF

echo "
[DEFAULT]
dhcpbridge_flagfile=/etc/nova/nova.conf
dhcpbridge=/usr/bin/nova-dhcpbridge
logdir=/var/log/nova
state_path=/var/lib/nova
lock_path=/var/lock/nova
root_helper=sudo nova-rootwrap /etc/nova/rootwrap.conf
verbose=True

api_paste_config=/etc/nova/api-paste.ini
enabled_apis=ec2,osapi_compute,metadata

# Libvirt and Virtualization
libvirt_use_virtio_for_bridges=True
connection_type=libvirt
libvirt_type=qemu

# Database
connection=mysql://nova:openstack@${MYSQL_HOST}/nova

# Messaging
rpc_backend=rabbit
rabbit_host=${MYSQL_HOST}

# EC2 API Flags
ec2_host=${MYSQL_HOST}
ec2_dmz_host=${MYSQL_HOST}
ec2_private_dns_show_ip=True

# VNC Settings
my_ip=${PUB_IP}
vncserver_listen=0.0.0.0
vncserver_proxyclient_address=${PUB_IP}
novncproxy_base_url=http://${PUB_IP}:6080/vnc_auto.html

# Network settings
network_api_class=nova.network.neutronv2.api.API
neutron_url=http://${MY_IP}:9696
neutron_auth_strategy=keystone
neutron_admin_tenant_name=service
neutron_admin_username=neutron
neutron_admin_password=neutron
neutron_admin_auth_url=http://${MY_IP}:35357/v2.0
libvirt_vif_driver=nova.virt.libvirt.vif.LibvirtHybridOVSBridgeDriver
linuxnet_interface_driver=nova.network.linux_net.LinuxOVSInterfaceDriver
#firewall_driver=nova.virt.libvirt.firewall.IptablesFirewallDriver
security_group_api=neutron
firewall_driver=nova.virt.firewall.NoopFirewallDriver

service_neutron_metadata_proxy=true
neutron_metadata_proxy_shared_secret=foo

#Metadata
#metadata_host = ${MYSQL_HOST}
#metadata_listen = ${MYSQL_HOST}
#metadata_listen_port = 8775

# Cinder #
volume_driver=nova.volume.driver.ISCSIDriver
enabled_apis=ec2,osapi_compute,metadata
volume_api_class=nova.volume.cinder.API
iscsi_helper=tgtadm
 #set private IP address for providing iSCSI storage to VMs
iscsi_ip_address = ${MY_IP}
 #may not be necessary
volume_name_template = volume-%s
 #LVM Group name generated by cinder.sh
volume_group = cinder-volumes


# Images
image_service=nova.image.glance.GlanceImageService
glance_api_servers=${GLANCE_HOST}:9292

# Scheduler
scheduler_default_filters=AllHostsFilter

# Object Storage <--- ??? Placeholder for Swift?
#iscsi_helper=tgtadm

# Auth
auth_strategy=keystone
keystone_ec2_url=http://${KEYSTONE_ENDPOINT}:5000/v2.0/ec2tokens

[keystone_authtoken]

auth_uri = http://${CONTROLLER_HOST}:5000
auth_host = ${CONTROLLER_HOST}
auth_protocol = http
auth_port = 35357
admin_tenant_name = service
admin_user = neutron
admin_password = neutron" | sudo tee -a $NOVA_CONF

sudo chmod 0640 $NOVA_CONF
sudo chown nova:nova $NOVA_CONF

# Paste file
sudo sed -i "s/127.0.0.1/$KEYSTONE_ENDPOINT/g" $NOVA_API_PASTE
sudo sed -i "s/%SERVICE_TENANT_NAME%/$SERVICE_TENANT/g" $NOVA_API_PASTE
sudo sed -i "s/%SERVICE_USER%/nova/g" $NOVA_API_PASTE
sudo sed -i "s/%SERVICE_PASSWORD%/$SERVICE_PASS/g" $NOVA_API_PASTE

sudo nova-manage db sync


# Restart services
sudo service nova-api restart
sudo service nova-cert restart
sudo service nova-consoleauth restart
sudo service nova-scheduler restart
sudo service nova-conductor restart
sudo service nova-novncproxy restart
sudo service nova-compute restart

###############################
# Cinder Installation
###############################

# Install the DB
MYSQL_ROOT_PASS=openstack
MYSQL_CINDER_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE cinder;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'%';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'cinder'@'%' = PASSWORD('$MYSQL_CINDER_PASS');"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'localhost';"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'cinder'@'localhost' = PASSWORD('$MYSQL_CINDER_PASS');"

sudo apt-get install -y --force-yes cinder-api cinder-scheduler cinder-volume lvm2

sudo mkdir -p /etc/cinder/backup
sudo cp -rf /etc/cinder/* /etc/cinder/backup/

# Configure Cinder
# /etc/cinder/api-paste.ini
sudo sed -i 's/127.0.0.1/'${CONTROLLER_HOST}'/g' /etc/cinder/api-paste.ini
sudo sed -i 's/%SERVICE_TENANT_NAME%/service/g' /etc/cinder/api-paste.ini
sudo sed -i 's/%SERVICE_USER%/cinder/g' /etc/cinder/api-paste.ini
sudo sed -i 's/%SERVICE_PASSWORD%/cinder/g' /etc/cinder/api-paste.ini

# OpenStack Controller Private IP for use with generating Cinder target IP
OSC_PRIV_IP=${CONTROLLER_HOST_PRIV}

# Define environment variable to contain the OpenStack Controller Private IP for use with Cinder
export OSCONTROLLER_P=$OSC_PRIV_IP

# /etc/cinder/cinder.conf
sudo cp /etc/cinder/cinder.conf /etc/cinder/cinder.conf.bak

echo "
[DEFAULT]
rootwrap_config = /etc/cinder/rootwrap.conf
connection = mysql://cinder:openstack@${CONTROLLER_HOST}/cinder
api_paste_config = /etc/cinder/api-paste.ini

iscsi_helper = tgtadm
volume_name_template = volume-%s
volume_group = cinder-volumes
verbose = True
auth_strategy = keystone
#osapi_volume_listen_port=5900

#set private IP address for providing iSCSI storage to VMs
iscsi_ip_address = $(echo $OSCONTROLLER_P | sed 's/\.[0-9]*$/.211/') 

# Add these when not using the defaults.
rpc_backend = cinder.openstack.common.rpc.impl_kombu
rabbit_host = ${CONTROLLER_HOST}
rabbit_port = 5672
state_path = /var/lib/cinder/
glance_host = ${CONTROLLER_HOST}

[keystone_authtoken]

auth_uri = http://${CONTROLLER_HOST}:5000
auth_host = ${CONTROLLER_HOST}
auth_protocol = http
auth_port = 35357
admin_tenant_name = service
admin_user = cinder
admin_password = cinder" | sudo tee -a /etc/cinder/cinder.conf

# Sync DB
sudo cinder-manage db sync

sudo umount /dev/vdb
sudo pvcreate /dev/vdb
sudo vgcreate cinder-volumes /dev/vdb

sudo service cinder-api restart
sudo service cinder-scheduler restart
sudo service cinder-volume restart
sudo service tgt restart

###############################
# Heat Installation
###############################

sudo apt-get install -y heat-api heat-api-cfn 
sudo apt-get install -y heat-engine

MYSQL_ROOT_PASS=openstack
MYSQL_HEAT_PASS=openstack
mysql -uroot -p$MYSQL_ROOT_PASS -e 'CREATE DATABASE heat;'
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON heat.* TO 'heat'@'%'"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'heat'@'%' = PASSWORD('$MYSQL_HEAT_PASS');"
mysql -uroot -p$MYSQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON heat.* TO 'heat'@'localhost'"
mysql -uroot -p$MYSQL_ROOT_PASS -e "SET PASSWORD FOR 'heat'@'localhost' = PASSWORD('$MYSQL_HEAT_PASS');"

sudo mkdir -p /etc/heat/backup
sudo cp -rf /etc/heat/* /etc/heat/backup/
sudo rm -f /etc/heat/api-paste.ini
echo "
# heat-api pipeline
[pipeline:heat-api]
pipeline = faultwrap versionnegotiation authtoken context apiv1app

# heat-api pipeline for standalone heat
# ie. uses alternative auth backend that authenticates users against keystone
# using username and password instead of validating token (which requires
# an admin/service token).
# To enable, in heat.conf:
#   [paste_deploy]
#   flavor = standalone
#
[pipeline:heat-api-standalone]
pipeline = faultwrap versionnegotiation authpassword context apiv1app

# heat-api pipeline for custom cloud backends
# i.e. in heat.conf:
#   [paste_deploy]
#   flavor = custombackend
#
[pipeline:heat-api-custombackend]
pipeline = faultwrap versionnegotiation context custombackendauth apiv1app

# heat-api-cfn pipeline
[pipeline:heat-api-cfn]
pipeline = cfnversionnegotiation ec2authtoken authtoken context apicfnv1app

# heat-api-cfn pipeline for standalone heat
# relies exclusively on authenticating with ec2 signed requests
[pipeline:heat-api-cfn-standalone]
pipeline = cfnversionnegotiation ec2authtoken context apicfnv1app

# heat-api-cloudwatch pipeline
[pipeline:heat-api-cloudwatch]
pipeline = versionnegotiation ec2authtoken authtoken context apicwapp

# heat-api-cloudwatch pipeline for standalone heat
# relies exclusively on authenticating with ec2 signed requests
[pipeline:heat-api-cloudwatch-standalone]
pipeline = versionnegotiation ec2authtoken context apicwapp

[app:apiv1app]
paste.app_factory = heat.common.wsgi:app_factory
heat.app_factory = heat.api.openstack.v1:API

[app:apicfnv1app]
paste.app_factory = heat.common.wsgi:app_factory
heat.app_factory = heat.api.cfn.v1:API

[app:apicwapp]
paste.app_factory = heat.common.wsgi:app_factory
heat.app_factory = heat.api.cloudwatch:API

[filter:versionnegotiation]
paste.filter_factory = heat.common.wsgi:filter_factory
heat.filter_factory = heat.api.openstack:version_negotiation_filter

[filter:faultwrap]
paste.filter_factory = heat.common.wsgi:filter_factory
heat.filter_factory = heat.api.openstack:faultwrap_filter

[filter:cfnversionnegotiation]
paste.filter_factory = heat.common.wsgi:filter_factory
heat.filter_factory = heat.api.cfn:version_negotiation_filter

[filter:cwversionnegotiation]
paste.filter_factory = heat.common.wsgi:filter_factory
heat.filter_factory = heat.api.cloudwatch:version_negotiation_filter

[filter:context]
paste.filter_factory = heat.common.context:ContextMiddleware_filter_factory

[filter:ec2authtoken]
paste.filter_factory = heat.api.aws.ec2token:EC2Token_filter_factory

# Auth middleware that validates token against keystone
[filter:authtoken]
paste.filter_factory = heat.common.auth_token:filter_factory
auth_host = $ENDPOINT
auth_port = 35357
auth_protocol = http
admin_tenant_name = service
admin_user = heat
admin_password = heat
auth_uri = http://$ENDPOINT:5000/v2.0/

# Auth middleware that validates username/password against keystone
[filter:authpassword]
paste.filter_factory = heat.common.auth_password:filter_factory

# Auth middleware that validates against custom backend
[filter:custombackendauth]
paste.filter_factory = heat.common.custom_backend_auth:filter_factory" | sudo tee -a /etc/heat/api-paste.ini

sudo sed -i "s,^connection.*,connection = mysql://heat:${MYSQL_HEAT_PASS}@${MYSQL_HOST}/heat," /etc/heat/heat.conf
sudo mkdir -p /etc/heat/environments.d
echo '

resource_registry:
    # allow older templates with Quantum in them.
    "OS::Quantum*": "OS::Neutron*"
    # Choose your implementation of AWS::CloudWatch::Alarm
    #"AWS::CloudWatch::Alarm": "file:///etc/heat/templates/AWS_CloudWatch_Alarm.yaml"
    "AWS::CloudWatch::Alarm": "OS::Heat::CWLiteAlarm"http://127.0.0.1:6080/vnc_auto.html?token=0aedc7b3-2701-4f78-8335-b7c25683f360&title=test-7d36d517-d17a-4d38-a5db-b70c479baed8(7d36d517-d17a-4d38-a5db-b70c479baed8)
    "OS::Metering::Alarm": "OS::Ceilometer::Alarm"
    "AWS::RDS::DBInstance": "file:///etc/heat/templates/AWS_RDS_DBInstance.yaml"
' | sudo tee -a /etc/heat/environments.d/default.yaml 

sudo service heat-api restart
sudo service heat-api-cfn restart
sudo service heat-engine restart

sudo heat-manage db_sync


###############################
# Dashboard Installation
###############################


sudo apt-get install -y --force-yes apache2 memcached libapache2-mod-wsgi openstack-dashboard

###############################
# OpenStack Deployment Complete
###############################

# Create a .stackrc file
cat > /home/ubuntu/.stackrc <<EOF
export OS_TENANT_NAME=interop
export OS_USERNAME=admin
export OS_PASSWORD=openstack
export OS_AUTH_URL=http://${MY_IP}:5000/v2.0/
EOF

