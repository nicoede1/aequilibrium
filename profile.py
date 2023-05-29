"""Test

Instructions:
Test"""

#
# NOTE: This code was machine converted. An actual human would not
#       write code like this!
#

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as rspec

# Create a portal object,
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

# Node ryu
node_ryu = request.XenVM('ryu')
node_ryu.routable_control_ip = True
node_ryu.Site('Site 1')
node_ryu.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'

# Node ovs
node_ovs = request.XenVM('ovs')
node_ovs.routable_control_ip = False
node_ovs.Site('Site 2')
node_ovs.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface0 = node_ovs.addInterface('interface-6')
iface1 = node_ovs.addInterface('interface-8')
iface2 = node_ovs.addInterface('interface-10')

# Node h1
node_h1 = request.XenVM('h1')
node_h1.routable_control_ip = False
node_h1.Site('Site 2')
node_h1.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface3 = node_h1.addInterface('interface-11')

# Node h3
node_h3 = request.XenVM('h3')
node_h3.routable_control_ip = False
node_h3.Site('Site 2')
node_h3.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface4 = node_h3.addInterface('interface-7')

# Node h2
node_h2 = request.XenVM('h2')
node_h2.routable_control_ip = False
node_h2.Site('Site 2')
node_h2.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface5 = node_h2.addInterface('interface-9')

# Link link-3
link_3 = request.Link('link-3')
link_3.Site('undefined')
link_3.addInterface(iface0)
link_3.addInterface(iface4)

# Link link-4
link_4 = request.Link('link-4')
link_4.Site('undefined')
link_4.addInterface(iface1)
link_4.addInterface(iface5)

# Link link-5
link_5 = request.Link('link-5')
link_5.Site('undefined')
link_5.addInterface(iface2)
link_5.addInterface(iface3)

# Install and execute a script that is contained in the repository.
node_ryu.addService(rspec.Execute(shell="/bin/sh", command="sudo apt -y update"))
node_ryu.addService(rspec.Execute(shell="/bin/sh", command="sudo apt-get install python-pip python-dev -y"))
node_ryu.addService(rspec.Execute(shell="/bin/sh", command="sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1"))
node_ryu.addService(rspec.Execute(shell="/bin/sh", command="sudo apt install -y python3-ryu"))
node_ovs.addService(rspec.Execute(shell="/bin/sh", command="sudo apt -y update"))
node_ovs.addService(rspec.Execute(shell="/bin/sh", command="sudo apt install -y openvswitch-switch"))
node_h1.addService(rspec.Execute(shell="/bin/sh", command="sudo apt -y update"))
node_h2.addService(rspec.Execute(shell="/bin/sh", command="sudo apt -y update"))
node_h3.addService(rspec.Execute(shell="/bin/sh", command="sudo apt -y update"))
node_h1.addService(rspec.Execute(shell="/bin/sh", command="sudo apt install -y apache2"))
node_h2.addService(rspec.Execute(shell="/bin/sh", command="sudo apt install -y apache2"))
node_h3.addService(rspec.Execute(shell="/bin/sh", command="sudo apt install -y apache2"))

# Print the generated rspec
pc.printRequestRSpec(request)
