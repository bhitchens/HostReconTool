#removed netaddr, math
import sqlite3, sys, socket, subprocess

class PSExecQuery:

	ipAddr = ""
	database = ""
	computerName = ""
	stout = False
	
	def __init__(self, remote, user, password):
		self.remote = remote
		self.user = user
		self.password = password
		self.w = None
		global ipAddr
		#if a remote IP has been provided, set the ipAddr global to that IP
		if remote != "":
			ipAddr = remote
		#else set it to the local system's IP
		else:
			ipAddr = socket.gethostbyname(socket.gethostname())
			
	def setComputerName(self):
		global computerName
		computerName = self.psexec("hostname")[-2]

	def psexec(self, command):
		list = ["psexec.exe", "-AcceptEULA", "\\\\" + ipAddr] + command.split(" ")
		#print list
		proc = subprocess.Popen(list, stdout=subprocess.PIPE)#, stderr=subprocess.STDOUT)
		return proc.stdout.read().split('\n')
		
	def all(self):
		self.netstat()
	
	def ports(self):
		global computerName
		results = self.psexec("netstat -anob")
		i = 0
		while "Proto" not in results[i]:
			i += 1
		i += 1
		j = i
		#fixed to run normally
		if self.database != "":# or 1==1:
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE open_ports (ComputerName TEXT, ipAddr text, Protocol text, LocalIP text, LocalPort text, ForeignIP text, ForeignPort text, State text, PID text, Owner text, unique (ComputerName, ipAddr, LocalIP, LocalPort, ForeignIP, ForeignPort))''')
			except sqlite3.OperationalError:
				pass	
			#try:
			while i < len(results) - 1:
				#print results[i]
				splitLine = results[i].split()
				#print splitLine
				local = splitLine[1].replace("::", ";;").split(':')
				localIP = ""						
				foreign = splitLine[2].replace("::",";;").split(':')
				i += 1
				owner = results[i].strip()
				i += 1
				if results[i].split()[0][0] == '[':
					owner += ' ' + results[i].strip()
					i += 1
				#print splitLine
				if splitLine[0] == "TCP":
					portsData = (computerName, ipAddr, splitLine[0], local[0].replace(";;", "::"), local[1], foreign[0].replace(";;", "::"), foreign[1], splitLine[3], splitLine[4], owner)
				else:
					portsData = (computerName, ipAddr, splitLine[0], local[0].replace(";;", "::"), local[1], foreign[0].replace(";;", "::"), foreign[1], "", splitLine[3], owner)
				try:
					c.execute('INSERT INTO open_ports VALUES (?,?,?,?,?,?,?,?,?,?)', portsData)
				except sqlite3.IntegrityError:
					pass					
			db.commit()
			db.close()
			
		if self.stout:
			while j < len(results):
				j += 1
				
