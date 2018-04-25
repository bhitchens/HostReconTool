from netaddr import IPNetwork
from multiprocessing import Process, Lock
import sys, netaddr, wmiqueries, psexecqueries, sqlite3, argparse

lock = Lock()

#Process provided switches; passed WMI connection
def runSwitches(connection, psexec, dbcheck, args):		

	#check new functions
	#psexec.route()
	#sys.exit()

	#check for -A/--all
	if "-A" in sys.argv or "--all" in sys.argv:
		connection.all()
		psexec.all()
		return
	i = 1
	
	#boolean for checking if sysData has already run
	#sysDataComplete = False
	if dbcheck:
		connection.sysData()
		computerName = connection.getComputerName()
	elif args.sysinfo:
		connection.sysData()
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

def analize(ipaddr, user, password, verbose, database, dbcheck, stout, args):
	remote = ipaddr
	connection = wmiqueries.WMIConnection(remote, user, password, verbose)
	db = sqlite3.connect(database)
	db.text_factory = str
	c = db.cursor()
	connection.connect(c)
	connection.database = database
	connection.stout = stout
	psexec = psexecqueries.PSExecQuery(remote, user, password, verbose)
	psexec.database = database
	psexec.connectDB(c)
	psexec.stout = stout
	psexec.setComputerName()
	runSwitches(connection, psexec, dbcheck, args)
	db.commit()
	db.close()

#main function
def main():
	#these lines allow non-ASCII characters
	reload(sys)
	sys.setdefaultencoding('utf-8')

	computerName = ""
		
	user = ""
	password = ""

	remote = ""
	database = ""
	stout = False
	verbose = False

	parser = argparse.ArgumentParser(description='Gather host data.')
	parser.add_argument("-d", "--db", nargs=1, help="Provide database name or full path to specify location")
	parser.add_argument("-o", "--stout", action='store_true', help="Send results to Standard Out")
	parser.add_argument("--verbose", action='store_true', help="Print verbose results")
	parser.add_argument("-i", "--ipaddr", nargs=1, help="IP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine")
	parser.add_argument("--username", action='store_true', help="User Name for remote system (must be used with -r)")
	parser.add_argument("--password", action='store_true', help="Password for remote system (must be used with -r and -u)")
	parser.add_argument("-A", "--all", action='store_true', help="Run all switches")
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

	#boolean for supplied database
	dbcheck = False
		
	#check for -d switch
	if (args.db):
		database = args.db[0]
		dbcheck = True

	#check for -o
	if (args.stout):
		stout = True
	
	#Confirm that either db stout are selected
	if ((not dbcheck) and (not stout)):
		print "Either -d or --db with database name or -o or --stout is required."
		sys.exit()
				
	#check for user name
	if (args.username):
		user = args.username
		
	#check for password
	if (user != ""):
		if (args.password):
			password = args.password
	elif (args.password):
		print "Password may only be supplied with username."
		sys.exit()

	#check for remote IP address switch
	ip = ""	
	if (args.ipaddr):
		ip = args.ipaddr[0]
	elif (user != ""):
		print "Username may only be provided with an ip address."
		sys.exit()
	else:
		print "No remote address, running on local machine."
			
	#check for verbose
	if (args.verbose):
		verbose = True

	#if there is a remote ip, run all of the switches on each machine
	if ip != "":
		try:
			for ipaddr in IPNetwork(ip):
				Process(target=analize, args=(ipaddr, user, password, verbose, database, dbcheck, stout, args)).start()
		except netaddr.core.AddrFormatError:
			print "Invalid network address"
			sys.exit()
			
	#no remote IP
	else:
		Process(target=analize, args=(remote, user, password, verbose, database, dbcheck, stout, args)).start()
		
if __name__ == "__main__":
	main()