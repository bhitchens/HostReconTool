from netaddr import IPNetwork
import sys, netaddr, wmiqueries

#these lines allow non-ASCII characters
reload(sys)
sys.setdefaultencoding('utf-8')

remote = ""
database = ""
stout = False

#Process provided switches; passed WMI connection
def runSwitches(connection):		
	#if len(sys.argv) == 3:
		#connection.sysData()	
	i = 1
	while i < len(sys.argv):
		arg = sys.argv[i]
		#error if there is an improperly formatted switch
		if arg[:1] != '-':
			print "Error: " + arg + " is not a valid parameter. Try \'-h\' or \'--help\' for a list of options."
			sys.exit()
		#automatically run sysData
		if i == 1:
			connection.sysData()
		#database, standard out, and remote switches have already been processed; skip them
		if arg == "-d" or arg == "--db" or arg == "-i" or arg == "--remote":
			i += 2
		elif arg == "-o" or arg == "--stout":
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
		elif arg == "-p" or arg == "--profiles":
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
	
#use this for testing
'''testWMIQuery()
sys.exit()'''

	
#Actual start is here

#help message
if "-h" in sys.argv or "--help" in sys.argv:
	helpStatement = "The following options are available:\n"
	helpStatement += "-h or --help:\t\tThis help text\n"
	helpStatement += "-d or --db:\t\tProvide database name or full path to specify location\n"
	helpStatement += "-o or --stout:\t\tSend results to Standard Out\n"
	helpStatement += "-i or --remote:\t\tIP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine\n"
	helpStatement += "-u or --users:\t\tUser account data\n"
	helpStatement += "-n or --netlogin:\t\tNetwork Login data\n"
	helpStatement += "-g or --groups:\t\tGroup data\n"
	helpStatement += "-l or --ldisks:\t\tLogical Disk data\n"
	helpStatement += "-t or --timezone:\tTimezone data\n"
	helpStatement += "-s or --startup:\tStartup Program data\n"
	helpStatement += "-p or --profiles:\tUser Profiles data\n"
	helpStatement += "-a or --adapters:\tNetork Adapter data\n"
	helpStatement += "-P or --process:\tProcesses data\n"
	helpStatement += "-S or --services:\tServices data\n"
	helpStatement += "-r or --shares:\t\tShared Resources data\n"
	helpStatement += "-D or --pdisks:\t\tPhysical Disk data\n"
	helpStatement += "-m or --memory:\t\tPhysical Memory data\n"
	print helpStatement
	sys.exit()

#check for -d switch
try:
	database = sys.argv[sys.argv.index("-d") + 1]
except ValueError:
	#if it's not there, check for --db
	try:
		database = sys.argv[sys.argv.index("--db") + 1]
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
			connection = wmiqueries.WMIConnection(remote)
			connection.connect()
			connection.database = database
			connection.stout = stout
			runSwitches(connection)
	except netaddr.core.AddrFormatError:
		print "Invalid network address"
		sys.exit()
#no remote IP
else:
	connection = wmiqueries.WMIConnection(remote)
	connection.connect()
	connection.database = database
	connection.stout = stout
	runSwitches(connection)