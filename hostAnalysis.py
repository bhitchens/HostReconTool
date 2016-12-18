from _winreg import *
from netaddr import IPNetwork
import sys, netaddr, wmiqueries

reload(sys)
sys.setdefaultencoding('utf-8')

remote = ""
database = ""
stout = False

def runSwitches(connection):		
	if len(sys.argv) == 3:
		connection.sysData()	
	i = 1
	while i < len(sys.argv):
		arg = sys.argv[i]
		if arg[:1] != '-':
			print "Error: " + arg + " is not a valid parameter. Try \'-h\' or \'--help\' for a list of options."
			sys.exit()
		if i == 1:
			connection.sysData()
		if arg == "-d" or arg == "--db":
			i += 2
		elif arg == "-r" or arg == "--remote":
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
		else:
			print "Error: unrecognized switch"
			sys.exit()
	return
	


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
	for item in connection.w.win32_Service():
		print item
	
#use this for testing
'''testWMIQuery()
sys.exit()'''

	
#Actual start is here
if "-h" in sys.argv or "--help" in sys.argv:
	helpStatement = "The following options are available:\n"
	helpStatement += "\t-h or --help:\t\tThis help text\n"
	helpStatement += "\t-d or --db:\t\tProvide database name or full path to specify location\n"
	helpStatement += "\t-o or --stout:\t\tSend results to Standard Out\n"
	helpStatement += "\t-r or --remote:\t\tIP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine\n"
	helpStatement += "\t-u or --users:\t\tUser account data\n"
	helpStatement += "\t-g or --groups:\t\tGroup data\n"
	helpStatement += "\t-l or --ldisks:\t\tLogical Disk data\n"
	helpStatement += "\t-t or --timezone:\tTimezone data\n"
	helpStatement += "\t-s or --startup:\tStartup Program data\n"
	helpStatement += "\t-p or --profiles:\tUser Profiles data\n"
	helpStatement += "\t-a or --adapters:\tNetork Adapter data\n"
	helpStatement += "\t-P or --process:\tProcesses data\n"
	helpStatement += "\t-S or --services:\Services data\n"
	print helpStatement
	sys.exit()

outputFail = False
	
try:
	database = sys.argv[sys.argv.index("-d") + 1]
except ValueError:
	try:
		database = sys.argv[sys.argv.index("--db") + 1]
	except ValueError:
		outputFail = True

try:
	sys.argv.index("-o")
	stout = True
except ValueError:
	try:
		sys.argv.index("--stout")
		stout = True
	except ValueError:
		if outputFail:
			print "Either -d or --db with database name or -o or --stout is required."
			sys.exit()

#check for remote IP address switch
ip = ""		
try:
	ip = sys.argv[sys.argv.index("-r") + 1]
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
			runSwitches(connection)
	except netaddr.core.AddrFormatError:
		print "Invalid network address"
		sys.exit()
else:
	connection = wmiqueries.WMIConnection(remote)
	connection.connect()
	connection.database = database
	connection.stout = stout
	runSwitches(connection)