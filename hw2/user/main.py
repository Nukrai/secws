#! /usr/bin/python
import sys
path = "/sys/class/Sysfs_class/sysfs_class_sysfs_Device/sysfs_att"
s = "Firewall Packets Summary:\nNumber of accepted packets: {0}\nNumber of dropped packets: {1}\nTotal number of packets: {2}"
if(len(sys.argv) == 1):
	with open(path,"r") as f:
		data = f.read().split(",")
		print(s.format(*data))
elif(len(sys.argv) == 2 and sys.argv[1]=="0"):
	with open(path,"w") as f:
		f.write("0")
else:
	print("Invalid arg. number OR the argument specified is not 0. please enter 0 args OR one arg - 0.")
