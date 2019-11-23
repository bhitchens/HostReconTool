from netaddr import IPNetwork
from multiprocessing import Process, Lock
import sys, netaddr, wmiqueries, psexecqueries, sqlite3, argparse
import importlib

def wmiConnect(ipaddr, verbose, lock, database, stout):
	global wmiSuccess
	global connection
	if connection is None and not wmiSuccess:
		try:
			#Create wmi object and set its database name and stout boolean
			connection = wmiqueries.WMIConnection(ipaddr, verbose, lock, database)	
			connection.database = database
			connection.stout = stout
			connection.connect()
			wmiSuccess = True
		except Exception:
			lock.acquire()
			if ipaddr == "":
				print("Failed to make WMI connection to localhost")
			else:
				print("Failed to make WMI connection to " + str(ipaddr))
			lock.release()
			wmiSuccess = False
	
	return connection
		
def psexecConnect(ipaddr, verbose, lock, database, stout):
	global pseSuccess
	global psexec
	if psexec is None and not pseSuccess:
		try:
			#create psexec object and set its database name, stout boolean
			psexec = psexecqueries.PSExecQuery(ipaddr, verbose, lock, database)
			psexec.database = database
			psexec.stout = stout
			#check to see if psexec is functional
			psexec.testPsexec()
			pseSuccess = True
		except Exception:
			lock.acquire()
			if ipaddr == "":
				print("Failed to make psexec connection to localhost")
			else:
				print("Failed to make psexec connection to " + str(ipaddr))
			lock.release()
			pseSuccess = False
	return psexec

#Sets up connections and triggers runSwitches
def analyze(ipaddr, verbose, database, stout, args, lock):
	#declare neccessary globals
	global wmiSuccess
	global pseSuccess
	global connection
	global psexec
	
	#initialize globals
	wmiSuccess = False
	pseSuccess = False
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
		connection = wmiConnect(ipaddr, verbose, lock, database, stout)
		psexec = psexecConnect(ipaddr, verbose, lock, database, stout)
		if wmiSuccess: connection.all()
		if pseSuccess: psexec.all()
		return
		
	#Run functions for all supplied flags
	if (args.users or args.netlogin or args.groups or args.ldisks or args.timezone or args.startup or args.profiles or args.adapters or args.process or args.services or args.shares or args.pdisks or args.memory or args.patches or args.bios or args.pnp or args.drivers or args.sysinfo or args.processors or args.os or args.products):
		connection = wmiConnect(ipaddr, verbose, lock, database, stout)
		if wmiSuccess:			
			if args.sysinfo: connection.sysData()
			if args.users: connection.userData()
			if args.netlogin: connection.netLogin()
			if args.groups: connection.groupData()
			if args.ldisks: connection.logicalDisks()
			if args.timezone: connection.timeZone()
			if args.startup: connection.startupPrograms()
			if args.profiles: connection.userProfiles()
			if args.adapters: connection.networkAdapters()
			if args.process: connection.processes()
			if args.services: connection.services()
			if args.shares: connection.shares()
			if args.pdisks: connection.physicalDisks()
			if args.memory: connection.physicalMemory()
			if args.patches: connection.patches()
			if args.bios: connection.bios()
			if args.pnp: connection.pnp()
			if args.drivers: connection.drivers()
			if args.processors: connection.processors()
			if args.os: connection.operatingSystem()
			if args.products: connection.products()
	
	if (args.ports or args.arp or args.wireless or args.routes):
		psexec = psexecConnect(ipaddr, verbose, lock, database, stout)
		if pseSuccess:
			if (args.ports): psexec.ports()
			if (args.arp): psexec.arp()
			if (args.wireless): psexec.wireless()
			if (args.routes): psexec.route()
		
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
	parser.add_argument("--processors", action='store_true', help="Processor Data")
	parser.add_argument("--os", action='store_true', help="Operating System Data")
	parser.add_argument("--products", action='store_true', help="Products Data (Slow - Not Included in --all")
	
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