from netaddr import IPNetwork
from multiprocessing import Process, Lock
from argparse import RawTextHelpFormatter
import sys, netaddr, wmiqueries, psexecqueries, sqlite3, argparse, importlib

def wmiConnect(ipaddr, verbose, lock, database, stout):
	global wmiSuccess
	global connection
	if connection is None and not wmiSuccess:
		try:
			#Create wmi object and set its database name and stout boolean
			connection = wmiqueries.WMIConnection(ipaddr, verbose, lock, database, stout)
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
			psexec = psexecqueries.PSExecQuery(ipaddr, verbose, lock, database, stout)
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
		
	wmiList = ("all", "all_system", "all_users", "all_hardware", "all_software", "all_network", "users", "netlogin", "groups", "ldisks", "timezone", "startup", "profiles", "adapters", "process", "services", "shares", "pdisks", "memory", "patches", "bios", "pnp", "drivers", "sysinfo", "processors", "os", "products", "vss")
	pseList = ("all", "all_network", "ports", "arp", "wireless", "routes")
		
	if "-q" in sys.argv or "--query" in sys.argv:
		#connection = wmiConnect(ipaddr, verbose, lock, database, stout)
		#psexec = psexecConnect(ipaddr, verbose, lock, database, stout)

		for query in args.query:
			if (query in wmiList):
				connection = wmiConnect(ipaddr, verbose, lock, database, stout)
				if wmiSuccess: eval("connection.{}()".format(query))
			if (query in pseList):
				psexec = psexecConnect(ipaddr, verbose, lock, database, stout)
				if pseSuccess: eval("psexec.{}()".format(query))
			if (query not in wmiList and query not in pseList):
				print("{} is not a valid query.".format(query))
		
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
	parser = argparse.ArgumentParser(description='Gather host data.', formatter_class=RawTextHelpFormatter)
	#Basic Settings
	parser.add_argument("-d", "--db", nargs=1, help="Provide database name or full path to specify location")
	parser.add_argument("-o", "--stout", action='store_true', help="Send results to Standard Out")
	parser.add_argument("-v", "--verbose", action='store_true', help="Print verbose results")
	parser.add_argument("-i", "--ipaddr", nargs=1, help="IP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine")
	
	#Groups
	optionsString = "Run groups of queries:\n"
	optionsString += ("\t{:<15} {:<20}\n" * 6).format(
	"all", "Run all queries",
	"all_system", "Run all system queries", 
	"all_users", "Run all users queries",
	"all_hardware", "Run all hardware queries",
	"all_software", "Run all software queries",
	"all_network", "Run all network queries")
	
	#Information about system
	optionsString += "Information about system:\n"
	optionsString += ("\t{:<15} {:<20}\n" * 6).format(
	"sysinfo", "Gather System Information", 
	"patches", "Currently Applied Patches (Quick Fix Engineering)",
	"timezone", "Timezone data", 
	"bios", "BIOS Data",
	"os", "Operating System Data",
	"vss", "Volume Shadow Copy Data")
	
	#Information about users
	optionsString += "\nInformation about users:\n"
	optionsString += ("\t{:<15} {:<20}\n" * 4).format(
	"users", "User account data",
	"netlogin", "Network Login data",
	"profiles", "User Profiles data",
	"groups", "Group data")
	
	#Information about hardware
	optionsString += "\nInformation about hardware:\n"
	optionsString += ("\t{:<15} {:<20}\n" * 5).format(
	"pdisks", "Physical Disk data",
	"ldisks", "Logical Disk data",
	"memory", "Physical Memory data",
	"processors", "Processor Data",
	"pnp", "Plug-n-play Devices Data")
	
	#Information about software
	optionsString += "\nInformation about software:\n"
	optionsString += ("\t{:<15} {:<20}\n" * 5).format(
	"startup", "Startup Program data",
	"drivers", "Drivers Data",
	"process", "Processes data",
	"services", "Services data",
	"products", "Products Data")
	
	#Information about network
	optionsString += "\nInformation about network:\n"
	optionsString += ("\t{:<15} {:<20}\n" * 6).format(
	"adapters", "Netork Adapter data",
	"ports", "Open Ports",
	"arp", "Arp Table Data",
	"routes", "Routing Table and Interface Data",
	"wireless", "Wireless Connection Data",
	"shares", "Shared Resources data")
	
	parser.add_argument("-q", "--query", nargs='+', help="List data to be queried.\n\n" + optionsString)
		
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