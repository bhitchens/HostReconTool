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
	if (args.all):
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


	#sysDataComplete = True	
	
	'''while i < len(sys.argv):
		arg = sys.argv[i]
		#error if there is an improperly formatted switch
		if arg[:1] != '-':
			print "Error: " + arg + " is not a valid parameter. Try \'-h\' or \'--help\' for a list of options."
			sys.exit()
		#automatically run sysData if using a database
		if dbcheck and not sysDataComplete:
			connection.sysData()
			computerName = connection.getComputerName()
			sysDataComplete = True
		#connection.drivers()
		#sys.exit()
		#database, standard out, and remote switches have already been processed; skip them
		if arg == "-d" or arg == "--db" or arg == "-i" or arg == "--remote" or arg == "--username" or arg == "--password":
			i += 2
		elif arg == "-o" or arg == "--stout" or arg == "-v" or arg == "--verbose":
			i += 1
		elif (arg == "-y" or arg == "--sysinfo") and not dbcheck:
			connection.sysData()
			i += 1
		#if we're using a database, -y is redundant, skip it
		elif (arg == "-y" or arg == "--sysinfo"):
			i += 1
		elif arg == "-u" or arg == "--users":
			connection.userData()
			i += 1
		elif arg == "-n" or arg == "--netlogin":
			connection.netLogin()
			i += 1
		elif arg == "-g" or arg == "--groups":
			connection.groupData()
			i += 1
		elif arg == "-l" or arg == "--ldisks":
			connection.logicalDisks()
			i += 1
		elif arg == "-t" or arg == "--timezone":
			connection.timeZone()
			i += 1
		elif arg == "-s" or arg == "--startup":
			connection.startupPrograms()
			i += 1
		elif arg == "--profiles":
			connection.userProfiles()
			i += 1
		elif arg == "-a" or arg == "--adapters":
			connection.networkAdapters()
			i += 1
		elif arg == "-P" or arg == "--process":
			connection.processes()
			i += 1
		elif arg == "-S" or arg == "--service":
			connection.services()
			i += 1
		elif arg == "-r" or arg == "--shares":
			connection.shares()
			i += 1
		elif arg == "-D" or arg == "--pdisks":
			connection.physicalDisks()
			i += 1
		elif arg == "-m" or arg == "--memory":
			connection.physicalMemory()
			i += 1
		elif arg == "-p" or arg == "--ports":
			psexec.ports()
			i += 1
		elif arg == "--patches":
			connection.patches()
			i += 1
		elif arg == "--arp":
			psexec.arp()
			i += 1
		elif arg == "-w" or arg == "--wireless":
			psexec.wireless()
			i += 1
		elif arg == "--routes":
			psexec.route()
			i += 1
		elif arg == "-b" or arg == "--bios":
			connection.bios()
			i += 1
		elif arg == "--pnp":
			connection.pnp()
			i += 1
		elif arg == "--drivers":
			connection.drivers()
			i += 1
		else:
			print "Error: unrecognized switch " + arg
			sys.exit()'''
	return
	

#the next two methods are for testing
	
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

#main function
def main():
	#these lines allow non-ASCII characters
	reload(sys)
	sys.setdefaultencoding('utf-8')

	#Readding computer name PK and u/n p/w
	computerName = ""
		
	user = ""
	password = ""
	#Readding computer name PK and u/n p/w end

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
	

	#help message
	'''if "-h" in sys.argv or "--help" in sys.argv:
		helpStatement = "The following options are available:\n"
		helpStatement += "-h or --help:\t\tThis help text\n"
		helpStatement += "-d or --db:\t\tProvide database name or full path to specify location\n"
		helpStatement += "-o or --stout:\t\tSend results to Standard Out\n"
		helpStatement += "-i or --remote:\t\tIP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine\n"
		helpStatement += "-u or --user:\t\tUser Name for remote system (must be used with -r)\n"
		helpStatement += "-p or --pass:\t\tPassword for remote system (must be used with -r and -u)\n"
		helpStatement += "-A or --all:\t\tRun all switches\n"
		helpStatement += "-u or --users:\t\tUser account data\n"
		helpStatement += "-n or --netlogin:\tNetwork Login data\n"
		helpStatement += "-g or --groups:\t\tGroup data\n"
		helpStatement += "-l or --ldisks:\t\tLogical Disk data\n"
		helpStatement += "-t or --timezone:\tTimezone data\n"
		helpStatement += "-s or --startup:\tStartup Program data\n"
		helpStatement += "      --profiles:\tUser Profiles data\n"
		helpStatement += "-a or --adapters:\tNetork Adapter data\n"
		helpStatement += "-P or --process:\tProcesses data\n"
		helpStatement += "-S or --services:\tServices data\n"
		helpStatement += "-r or --shares:\t\tShared Resources data\n"
		helpStatement += "-D or --pdisks:\t\tPhysical Disk data\n"
		helpStatement += "-m or --memory:\t\tPhysical Memory data\n"
		helpStatement += "-p or --ports:\t\tOpen Ports\n"
		helpStatement += "      --patches:\tCurrently Applied Patches\n"
		helpStatement += "      --arp:\t\tArp Table Data"
		helpStatement += "      --routes:\t\tRouting Table Data"
		print helpStatement
		sys.exit()'''

	#boolean for supplied database
	dbcheck = False
		
	#check for -d switch
	if (args.db):
		database = args.db[0]
		dbcheck = True

	#check for -o
	if (args.stout):
		stout = True
		
	if ((not dbcheck) and (not stout)):
		print "Either -d or --db with database name or -o or --stout is required."
		sys.exit()
				
	#check for user name
	if (args.username):
		user = args.username
	else:
		user = ""
	'''try:
		try:
			user = sys.argv[sys.argv.index("--username") + 1] 
		except ValueError:
			user = ""
	except IndexError:
		print "Username must be supplied with --username\nAttempting to procede with no username"
		user = ""'''
		
	#check for password
	if (user != ""):
		if (args.password):
			password = args.password
		else:
			password = ""
	elif (args.password):
		print "Password may only be supplied with username."
		sys.exit()
	'''try:
		try:
			password = sys.argv[sys.argv.index("--password") + 1]
		except ValueError:
			password = ""
	except IndexError:
		print "Password must be supplied with --password\nAttempting to procede with no password"
		password = ""'''

	#check for remote IP address switch
	ip = ""	
	if (args.ipaddr):
		ip = args.ipaddr
	elif (user != ""):
		print "Username may only be provided with an ip address."
		sys.exit()
	else:
		print "No remote address, running on local machine."
	'''try:
		ip = sys.argv[sys.argv.index("-i") + 1]
	except ValueError:
		try:
			ip = sys.argv[sys.argv.index("--remote") + 1]
		except ValueError:
			print "No remote address, running on local machine."'''
			
	#check for verbose
	if (args.verbose):
		verbose = True
	else:
		verbose = False;
	'''try:
		sys.argv.index("-v")
		verbose = True
	except ValueError:
		try:
			sys.argv.index("--verbose")
			verbose = True
		except ValueError:
			verbose = False'''

	#if there is a remote ip, run all of the switches on each machine
	if ip != "":
		try:
			for ipaddr in IPNetwork(ip):
				remote = ipaddr
				connection = wmiqueries.WMIConnection(remote, user, password, verbose)
				db = sqlite3.connect(database)
				db.text_factory = str
				c = db.cursor()
				connection.connect()
				connection.database = database
				connection.stout = stout
				#connection.bios()
				psexec = psexecqueries.PSExecQuery(remote, user, password, verbose)
				psexec.database = database
				psexec.connectDB(c)
				psexec.stout = stout
				#psexec.arp()
				psexec.setComputerName()
				runSwitches(connection, psexec, dbcheck, args)
		except netaddr.core.AddrFormatError:
			print "Invalid network address"
			sys.exit()
			
	#no remote IP
	else:
		connection = wmiqueries.WMIConnection(remote, user, password, verbose)
		db = sqlite3.connect(database)
		db.text_factory = str
		c = db.cursor()
		connection.connect(c)
		connection.database = database
		connection.stout = stout
		psexec = psexecqueries.PSExecQuery(remote, user, password, verbose)
		psexec.connectDB(c)
		psexec.database = database
		psexec.stout = stout
		psexec.setComputerName()
		runSwitches(connection, psexec, dbcheck, args)
		db.commit()
		db.close()
		
if __name__ == "__main__":
	main()