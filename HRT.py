from netaddr import IPNetwork
from multiprocessing import Process, Lock
import sys, netaddr, wmiqueries, psexecqueries, sqlite3, argparse
import importlib

def wmiCall(ipaddr, verbose, lock, database, stout, function):
	global wmiFail
	global connection
	if connection is None and not wmiFail:
		try:
			#Create wmi object and set its database name and stout boolean
			connection = wmiqueries.WMIConnection(ipaddr, verbose, lock, database)	
			connection.database = database
			connection.stout = stout
			connection.connect()
			eval("connection.%s" % (function))
		except Exception:
			lock.acquire()
			if ipaddr == "":
				print("Failed to make WMI connection to localhost")
			else:
				print("Failed to make WMI connection to " + str(ipaddr))
			lock.release()
			wmiFail = True
	return connection
		
def psexecCall(ipaddr, verbose, lock, database, stout, function):
	global pseFail
	global psexec
	if psexec is None and not pseFail:
		try:
			#create psexec object and set its database name, stout boolean
			psexec = psexecqueries.PSExecQuery(ipaddr, verbose, lock, database)
			psexec.database = database
			psexec.stout = stout
			#check to see if psexec is functional
			psexec.testPsexec()
			eval("psexec.%s" % (function))
		except Exception:
			lock.acquire()
			if ipaddr == "":
				print("Failed to make psexec connection to localhost")
			else:
				print("Failed to make psexec connection to " + str(ipaddr))
			lock.release()
			pseFail = True
	return psexec

#Sets up connections and triggers runSwitches
def analyze(ipaddr, verbose, database, stout, args, lock):
	#declare neccessary globals
	global wmiFail
	global pseFail
	global connection
	global psexec
	
	#initialize globals
	wmiFail = False
	pseFail = False
	connection = None
	psexec = None
	
	lock.acquire()
	if ipaddr == "":
		print("Starting localhost.")
	else:
		print("Starting " + str(ipaddr) + ".")
	lock.release()

	#Run functions based on switches
	#check for -A/--all
	if "-A" in sys.argv or "--all" in sys.argv:
		if not wmiFail: wmiCall(ipaddr, verbose, lock, database, stout, "all()")
		if not pseFail: psexecCall(ipaddr, verbose, lock, database, stout, "all()")
		return
		
	#Run functions for all supplied flags
	if not wmiFail:
		if (args.users): wmiCall(ipaddr, verbose, lock, database, stout, "userData()")
		if (args.netlogin): wmiCall(ipaddr, verbose, lock, database, stout, "netLogin()")
		if (args.groups): wmiCall(ipaddr, verbose, lock, database, stout, "groupData()")
		if (args.ldisks): wmiCall(ipaddr, verbose, lock, database, stout, "logicalDisks()")
		if (args.timezone): wmiCall(ipaddr, verbose, lock, database, stout, "timeZone()")
		if (args.startup): wmiCall(ipaddr, verbose, lock, database, stout, "startupPrograms()")
		if (args.profiles): wmiCall(ipaddr, verbose, lock, database, stout, "userProfiles()")
		if (args.adapters): wmiCall(ipaddr, verbose, lock, database, stout, "networkAdapters()")
		if (args.process): wmiCall(ipaddr, verbose, lock, database, stout, "processes()")
		if (args.services): wmiCall(ipaddr, verbose, lock, database, stout, "services()")
		if (args.shares): wmiCall(ipaddr, verbose, lock, database, stout, "shares()")
		if (args.pdisks): wmiCall(ipaddr, verbose, lock, database, stout, "physicalDisks()")
		if (args.memory): wmiCall(ipaddr, verbose, lock, database, stout, "physicalMemory()")
		if (args.patches): wmiCall(ipaddr, verbose, lock, database, stout, "patches()")
		if (args.bios): wmiCall(ipaddr, verbose, lock, database, stout, "bios()")
		if (args.pnp): wmiCall(ipaddr, verbose, lock, database, stout, "pnp()")
		if (args.drivers): wmiCall(ipaddr, verbose, lock, database, stout, "drivers()")
		if args.sysinfo: wmiCall(ipaddr, verbose, lock, database, stout, "sysData()")
	if not pseFail:
		if (args.ports): psexecCall(ipaddr, verbose, lock, database, stout, "ports()")
		if (args.arp): psexecCall(ipaddr, verbose, lock, database, stout, "arp()")
		if (args.wireless): psexecCall(ipaddr, verbose, lock, database, stout, "wireless()")
		if (args.routes): psexecCall(ipaddr, verbose, lock, database, stout, "route()")
		
	lock.acquire()
	if ipaddr == "":
		print("localhost complete.")
	else:
		print(str(ipaddr) + " complete.")
	lock.release()

#main function
def main():
	#these lines allow non-ASCII characters
	importlib.reload(sys)

	database = ""
	stout = False
	verbose = False

	#parse arguments
	parser = argparse.ArgumentParser(description='Gather host data.')
	parser.add_argument("-d", "--db", nargs=1, help="Provide database name or full path to specify location")
	parser.add_argument("-o", "--stout", action='store_true', help="Send results to Standard Out")
	parser.add_argument("--verbose", action='store_true', help="Print verbose results")
	parser.add_argument("-i", "--ipaddr", nargs=1, help="IP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine")
	parser.add_argument("--username", nargs=1, help="User Name for remote system (must be used with -i)")
	parser.add_argument("--password", nargs=1, help="Password for remote system (must be used with -i and -u)")
	parser.add_argument("-A", "--all", action='store_true', help="Run all switches")
	parser.add_argument("-y", "--sysinfo", action='store_true', help="Gather System Information")
	parser.add_argument("-u", "--users", action='store_true', help="User account data")
	parser.add_argument("-n", "--netlogin", action='store_true', help="Network Login data")
	parser.add_argument("-g", "--groups", action='store_true', help="Group data")
	parser.add_argument("-l", "--ldisks", action='store_true', help="Logical Disk data")
	parser.add_argument("-t", "--timezone", action='store_true', help="Timezone data")
	parser.add_argument("-s", "--startup", action='store_true', help="Startup Program data")
	parser.add_argument("--profiles", action='store_true', help="User Profiles data")
	parser.add_argument("-a", "--adapters", action='store_true', help="Netork Adapter data")
	parser.add_argument("-P", "--process", action='store_true', help="Processes data")
	parser.add_argument("-S", "--services", action='store_true', help="Services data")
	parser.add_argument("-r", "--shares", action='store_true', help="Shared Resources data")
	parser.add_argument("-D", "--pdisks", action='store_true', help="Physical Disk data")
	parser.add_argument("-m", "--memory", action='store_true', help="Physical Memory data")
	parser.add_argument("-p", "--ports", action='store_true', help="Open Ports")
	parser.add_argument("--patches", action='store_true', help="Currently Applied Patches")
	parser.add_argument("--arp", action='store_true', help="Arp Table Data")
	parser.add_argument("--routes", action='store_true', help="Routing Table and Interface Data")
	parser.add_argument("-w", "--wireless", action='store_true', help="Wireless Connection Data")
	parser.add_argument("-b", "--bios", action='store_true', help="BIOS Data")
	parser.add_argument("--pnp", action='store_true', help="Plug-n-play Devices Data")
	parser.add_argument("--drivers", action='store_true', help="Drivers Data")
	
	args = parser.parse_args()
		
	#check for -d switch
	if (args.db):
		database = args.db[0]
		dbcheck = True

	#check for -o
	if (args.stout):
		stout = True
	
	#Confirm that either db stout are selected
	if ((database == "") and (not stout)):
		print("Either -d or --db with database name or -o or --stout is required.")
		sys.exit()

	#check for remote IP address switch
	ip = ""	
	if (args.ipaddr):
		ip = args.ipaddr[0]
	else:
		print("No remote address, running on local machine.")
			
	#check for verbose
	if (args.verbose):
		verbose = True
		
	#Create lock
	lock = Lock()

	#if there is a remote ip, run all of the switches on each machine
	if ip != "":
		try:
			for ipaddr in IPNetwork(ip):
				Process(target=analyze, args=(ipaddr, verbose, database, stout, args, lock)).start()
		except netaddr.core.AddrFormatError:
			print("Invalid network address")
			sys.exit()
			
	#no remote IP
	else:
		Process(target=analyze, args=("", verbose, database, stout, args, lock)).start()
		
if __name__ == "__main__":
	main()