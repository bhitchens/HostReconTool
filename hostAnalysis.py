from netaddr import IPNetwork
import sys, netaddr, wmiqueries, psexecqueries

#these lines allow non-ASCII characters
reload(sys)
sys.setdefaultencoding('utf-8')

#Readding computer name PK and u/n p/w
computerName = ""
	
mUser = ""
mPassword = ""
#Readding computer name PK and u/n p/w end

remote = ""
database = ""
stout = False

#Process provided switches; passed WMI connection
def runSwitches(connection, psexec, dbcheck):		

	#check new functions
	#psexec.route()
	#sys.exit()

	#check for -A/--all
	if "-A" in sys.argv or "--all" in sys.argv:
		connection.all()
		psexec.all()
		sys.exit()
	i = 1
	while i < len(sys.argv):
		arg = sys.argv[i]
		#print arg
		#error if there is an improperly formatted switch
		if arg[:1] != '-':
			print "Error: " + arg + " is not a valid parameter. Try \'-h\' or \'--help\' for a list of options."
			sys.exit()
		#automatically run sysData if using a database
		if dbcheck:
			connection.sysData()
			computerName = connection.getComputerName()
			#print computerName
		if database != "":
			computerName = connection.getComputerName()
		#database, standard out, and remote switches have already been processed; skip them
		if arg == "-d" or arg == "--db" or arg == "-i" or arg == "--remote" or arg == "--username" or arg == "--password":
			i += 2
		elif arg == "-o" or arg == "--stout":
			i += 1
		elif (arg == "-y" or arg == "--sysinfo") and not dbcheck:
			connection.sysData()
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
		else:
			print "Error: unrecognized switch"
			sys.exit()
	return
	

#the next two methods are for testing
	
def testDBQuery():
	db = sqlite3.connect('data.db')
	c = db.cursor()
	for row in c.execute('SELECT SID, Name FROM user_data'): print row
	db.close()

def testWMIQuery():
	connection = wmiqueries.WMIConnection(remote)
	connection.connect()
	connection.database = database
	connection.stout = stout
	for item in connection.w.Win32_PhysicalMemory():
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

	
#Actual start is here

#help message
if "-h" in sys.argv or "--help" in sys.argv:
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
	print helpStatement
	sys.exit()

#boolean for supplied database
dbcheck = False
	
#check for -d switch
try:
	database = sys.argv[sys.argv.index("-d") + 1]
	dbcheck = True
except ValueError:
	#if it's not there, check for --db
	try:
		database = sys.argv[sys.argv.index("--db") + 1]
		dbcheck = True
	except ValueError:
		#if it's not there, hopefully -o/--stout is there
		pass

#check for -o
try:
	sys.argv.index("-o")
	stout = True
except ValueError:
	#if it's not there, check for --stout
	try:
		sys.argv.index("--stout")
		stout = True
	except ValueError:
		#if no -o/--stout, check to see if the database was set
		if database == "":
			#if neither standard out or a db were provided, it is an error
			print "Either -d or --db with database name or -o or --stout is required."
			sys.exit()
			
#check for user name
try:
	try:
		user = sys.argv[sys.argv.index("--username") + 1] 
		#print user
	except ValueError:
		user = ""
except IndexError:
	print "Username must be supplied with --username\nAttempting to procede with no username"
	user = ""
	
#check for password
try:
	try:
		password = sys.argv[sys.argv.index("--password") + 1]
	except ValueError:
		password = ""
except IndexError:
	print "Password must be supplied with --password\nAttempting to procede with no password"
	password = ""

#check for remote IP address switch
ip = ""		
try:
	ip = sys.argv[sys.argv.index("-i") + 1]
except ValueError:
	try:
		ip = sys.argv[sys.argv.index("--remote") + 1]
	except ValueError:
		print "No remote address, running on local machine."

#if there is a remote ip, run all of the switches on each machine
if ip != "":
	try:
		for ipaddr in IPNetwork(ip):
			remote = ipaddr
			connection = wmiqueries.WMIConnection(remote, user, password)
			connection.connect()
			connection.database = database
			connection.stout = stout
			psexec = psexecqueries.PSExecQuery(remote, user, password)
			psexec.database = database
			psexec.stout = stout
			psexec.setComputerName()
			runSwitches(connection, psexec, dbcheck)
	except netaddr.core.AddrFormatError:
		print "Invalid network address"
		sys.exit()
		
#no remote IP
else:
	connection = wmiqueries.WMIConnection(remote, user, password)
	connection.connect()
	connection.database = database
	connection.stout = stout
	psexec = psexecqueries.PSExecQuery(remote, user, password)
	psexec.database = database
	psexec.stout = stout
	psexec.setComputerName()
	runSwitches(connection, psexec, dbcheck)