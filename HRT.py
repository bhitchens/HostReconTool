from netaddr import IPNetwork
from multiprocessing import Process
import sys, netaddr, wmiqueries, psexecqueries, sqlite3, argparse

#Process provided switches; passed WMI connection
def runSwitches(connection, psexec, database, args):		

	#check for -A/--all
	if "-A" in sys.argv or "--all" in sys.argv:
		connection.all()
		psexec.all()
		return

	#If using a database, run sysdata to get computer name
	if database != "":
		connection.sysData()
		computerName = connection.getComputerName()
	#Otherwise only run sysdata if the sysinfo flag is supplied
	elif args.sysinfo:
		connection.sysData()
		
	#Run functions for all supplied flags
	if (args.users): connection.userData()
	if (args.netlogin): connection.netLogin()
	if (args.groups): connection.groupData()
	if (args.ldisks): connection.logicalDisks()
	if (args.timezone): connection.timeZone()
	if (args.startup): connection.startupPrograms()
	if (args.profiles): connection.userProfiles()
	if (args.adapters): connection.networkAdapters()
	if (args.process): connection.processes()
	if (args.services): connection.services()
	if (args.shares): connection.shares()
	if (args.pdisks): connection.physicalDisks()
	if (args.memory): connection.physicalMemory()
	if (args.patches): connection.patches()
	if (args.bios): connection.bios()
	if (args.pnp): connection.pnp()
	if (args.drivers): connection.drivers()
	if (args.ports): psexec.ports()
	if (args.arp): psexec.arp()
	if (args.wireless): psexec.wireless()
	if (args.routes): psexec.route()
	
	return	

#the following methods are for testing
	
def testDBQuery():
	db = sqlite3.connect('data.db')
	c = db.cursor()
	for row in c.execute('SELECT SID, Name FROM user_data'): print row
	db.close()

def testWMIQuery():
	connection = wmiqueries.WMIConnection(remote, "", "")
	connection.connect()
	connection.database = database
	connection.stout = stout
	for item in connection.w.Win32_DriverVXD ():
		print item
	
def testPsexQuery():
	user = ""
	password = ""
	psexec = psexecqueries.PSExecQuery(remote, user, password)
	psexec.database = database
	psexec.stout = stout
	psexec.setComputerName()
	psexec.arp()
#use this for testing
#testWMIQuery()
#testPsexQuery()
#sys.exit()

#Sets up connections and triggers runSwitches
def analyze(ipaddr, verbose, database, stout, args):
	try:
		#Create wmi object and set its database name and stout boolean
		connection = wmiqueries.WMIConnection(ipaddr, verbose)	
		connection.database = database
		connection.stout = stout
		connection.connect()		
	except Exception:
		print "Failed to make WMI connection to " + str(ipaddr)
		sys.exit()
		
	try:	
		#create psexec object and set its database name, stout boolean, and computer name
		psexec = psexecqueries.PSExecQuery(ipaddr, verbose)
		psexec.database = database
		psexec.stout = stout
		psexec.setComputerName()
	except Exception:
		print "Failed to make psexec connection to " + str(ipaddr)
		
	#if a DB is being used, create it and pass the cursor to the WMI and psexec objects
	if (database != ""):
		db = sqlite3.connect(database)
		db.text_factory = str
		c = db.cursor()	
		connection.connectDB(c)	
		psexec.connectDB(c)
	
	#Run functions based on switches
	runSwitches(connection, psexec, database, args)
	
	#if a DB is being used, commit values and close the DB
	if (database != ""):
		db.commit()
		db.close()
	

#main function
def main():
	#these lines allow non-ASCII characters
	reload(sys)
	sys.setdefaultencoding('utf-8')

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
	parser.add_argument("--routes", action='store_true', help="Routing Table Data")
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
		print "Either -d or --db with database name or -o or --stout is required."
		sys.exit()

	#check for remote IP address switch
	ip = ""	
	if (args.ipaddr):
		ip = args.ipaddr[0]
	else:
		print "No remote address, running on local machine."
			
	#check for verbose
	if (args.verbose):
		verbose = True

	#if there is a remote ip, run all of the switches on each machine
	if ip != "":
		try:
			for ipaddr in IPNetwork(ip):
				Process(target=analyze, args=(ipaddr, verbose, database, stout, args)).start()
		except netaddr.core.AddrFormatError:
			print "Invalid network address"
			sys.exit()
			
	#no remote IP
	else:
		Process(target=analyze, args=("", verbose, database, stout, args)).start()
		
if __name__ == "__main__":
	main()