openstackonocs
==============

Repository for hosting an automated script which will launch an instance of OpenStack on Cloudscaling's OCS Go demo system

This script requires that you have access to the Cloudscaling OCS Demo System.  Prior to launching you should also have an
SSH Access Key setup in the OCS Go Demo System.

In order to launch an OpenStack demo environment:

1.  Login to the OCS Go system at https://ocs.go.cloudscaling.com/horizon
2.  Launch a new Instance with the following settings:
	Source: Snapshot - "Interop_snapshot"
	Flavor: m1.large (or bigger)
	Access Key: Your Key (required in order to access the instance via SSH)
	Post-Creation Script: Paste the contents of openstackonocs.sh
3.  Click Launch

You can also use the nova CLI to launch the instance using the --user-data switch to pass in the shell script.

example 'nova boot --flavor m1.large --image precise-amd64 --key-name my_key --user-data openstackonocs.sh my_openstack_cloud'

The instance should build automatically and become available in approximately 5 minutes.  You can monitor the progress
of the script in the log files which are accessible through the Horizon Dashboard.
