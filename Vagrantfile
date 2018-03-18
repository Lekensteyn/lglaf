# -*- mode: ruby -*-
# vi: set ft=ruby :
# Author: David Manouchehri

Vagrant.configure("2") do |config|
	config.vm.box = "bento/ubuntu-16.04"

	# config.vm.synced_folder ".", "/vagrant", disabled: true

	config.vm.provision "docker" do |d|
		d.build_image '/vagrant/.', args: "-t lglaf"
		d.run "lglaf",
			args: "--privileged -it -v '/dev/bus/usb:/dev/bus/usb'"
	end

	%w(vmware_fusion vmware_workstation vmware_appcatalyst).each do |provider|
		config.vm.provider provider do |v|
			# v.vmx["memsize"] = "2048"
			v.vmx['ethernet0.virtualDev'] = 'vmxnet3'
			v.vmx["usb.vbluetooth.startConnected"] = "FALSE"
			v.vmx["usb.present"] = "TRUE"
			v.vmx["usb_xhci.present"] = "FALSE"
			v.vmx["usb.generic.autoconnect"] = "FALSE"
			v.vmx["usb.autoConnect.device0"] = "0x1004:0x633E"
			v.vmx["usb.autoConnect.device1"] = "0x1004:0x627F"
			v.vmx["usb.autoConnect.device2"] = "0x1004:0x6298"
			v.vmx["usb.autoConnect.device3"] = "0x1004:0x633A"
		end
	end
end
