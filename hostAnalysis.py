from _winreg import *
from netaddr import IPNetwork
import sys, netaddr, wmiqueries

remote = ""
database = ""

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
		elif arg == "-a" or arg == "--account":
			connection.userData()
			i += 1
		elif arg == "-n" or arg == "--netlogin":
			connection.netLogin()
			i += 1
		elif arg == "-g" or arg == "--groups":
			connection.groupData()
			i += 1
		elif arg == "--ldisks":
			connection.logicalDisks()
			i += 1
		elif arg == "-t" or arg == "--timezone":
			connection.timeZone()
			i += 1
		elif arg == "-s" or arg == "--startup":
			connection.startupPrograms()
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
	w = connect()
	for item in w.Win32_StartupCommand():
		print item
	
#use this for testing
'''testWMIQuery()
sys.exit()'''
	
	
#Actual start is here	

if "-h" in sys.argv or "--help" in sys.argv:
	helpStatement = "The following options are available:\n"
	helpStatement += "\t-h or --help:\tThis help text\n"
	helpStatement += "\t-d or --db:\t(Required) Provide full path for database location or just name to save in same directory as script\n"
	helpStatement += "\t-r or --remote:\tIP Address or CIDR-Notation range of IP Addresses. Exclude for Local Machine\n"
	helpStatement += "\t-a or --account:User account data\n"
	helpStatement += "\t-g or --groups:\tGroup data\n"
	helpStatement += "\t-l or --ldisks:\tLogical Disk data\n"
	helpStatement += "\t-t or --timezone:Timezone data\n"
	helpStatement += "\t-s or --startup:Startup Program data\n"
	print helpStatement
	sys.exit()

try:
	database = sys.argv[sys.argv.index("-d") + 1]
except ValueError:
	try:
		database = sys.argv[sys.argv.index("--db") + 1]
	except ValueError:
		print "Error: Database name must be included using -d or --db"
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
			runSwitches(connection)
	except netaddr.core.AddrFormatError:
		print "Invalid network address"
		sys.exit()
else:
	connection = wmiqueries.WMIConnection(remote, user, password)
	connection.connect()
	connection.database = database
	runSwitches(connection)