import sys
import angr
import logging
import datetime
import boltons.timeutils

import winproject	
				
if __name__ == '__main__':
	start_time = datetime.datetime.utcnow()
	logging.getLogger('angr').setLevel('FATAL')

	if len(sys.argv) <= 1:
		print("[!] Usage: %s driverPath" % sys.argv[0])
		sys.exit()

	driver = winproject.WDMDriverAnalysis(sys.argv[1], allowed_call_mode=True)

	if not driver.isWDM():
		print("[!] '%s' is not a WDM driver." % sys.argv[1])
		sys.exit()
	
	device_name = driver.find_device_name()
	print("[+] Device Name : %s" % device_name)

	mj_device_control_func = driver.find_DispatchDeviceControl()
	print("[+] DispatchIRP function : 0x%x" % mj_device_control_func)

	ioctl_interface = driver.recovery_ioctl_interface()
	import pprint
	pp = pprint.PrettyPrinter(indent=4)
	print("[+] IOCTL Interface :")
	pp.pprint(ioctl_interface)	

	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	print("[*] completed in: {0:.1f} {1}".format(*elapsed))
