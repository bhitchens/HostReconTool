#removed netaddr, math
import sqlite3, sys, socket, subprocess, re, os

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
			ipAddr = str(remote)
		#else set it to the local system's IP
		else:
			ipAddr = socket.gethostbyname(socket.gethostname())
			
	def setComputerName(self):
		global computerName
		computerName = self.psexec("hostname")[-2]
		print "Computer Name: " + computerName

	def psexec(self, command):
		#TODO: should receive stderr and check for success/failure
		FNULL = open(os.devnull, 'w')
		if self.password != "":
			list = ["psexec.exe", "-AcceptEULA", "\\\\" + str(ipAddr), "-h", "-u", self.user, "-p", self.password] + command.split(" ")
			proc = subprocess.Popen(list, stdout=subprocess.PIPE, stderr=FNULL)
			FNULL.close()
			return proc.stdout.read().split('\n')
		elif self.user != "":
			list = ["psexec.exe", "-AcceptEULA", "\\\\" + str(ipAddr), "-h", "-u", self.user] + command.split(" ")
			proc = subprocess.Popen(list, stdout=subprocess.PIPE, stderr=FNULL)
			FNULL.close()
			return proc.stdout.read().split('\n')
		list = ["psexec.exe", "-AcceptEULA", "-h", "\\\\" + str(ipAddr), "-h"] + command.split(" ")
		FNULL = open(os.devnull, 'w')
		proc = subprocess.Popen(list, stdout=subprocess.PIPE, stderr=FNULL)
		FNULL.close()		
		return proc.stdout.read().split('\n')
		
	def all(self):
		self.ports()
		self.route()
		self.arp()
	
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
				splitLine = results[i].split()
				local = splitLine[1].replace("::", ";;").split(':')
				localIP = ""						
				foreign = splitLine[2].replace("::",";;").split(':')
				i += 1
				owner = ""
				if "TIME_WAIT" not in results[i-1]:
					owner = results[i].strip()
					i += 1
					if results[i].split()[0][0] == '[':
						owner += ' ' + results[i].strip()
						i += 1
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
	
				
	def route(self):
		global computerName
		results = self.psexec("route print")
		i = 0
		#TODO: Change Proto
		while "Interface List" not in results[i]:
			i += 1
		i += 1
		j = i
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()	
				c.execute('''CREATE TABLE interface_list (ComputerName TEXT, ipAddr text, Interface text, MAC text, Label text, unique (ComputerName, ipAddr, Interface))''')
			except sqlite3.OperationalError:
				pass
			while "===" not in results[i]:
				resultsList = re.sub('\.\.+', ';;', results[i]).split(";;")
				if len(resultsList) == 3:
					interfaceData = (computerName, ipAddr, resultsList[0], resultsList[1], resultsList[2])
				else:
					interfaceData = (computerName, ipAddr, resultsList[0], "", resultsList[1])
				try:
					c.execute('INSERT INTO interface_list VALUES (?,?,?,?,?)', interfaceData)
				except sqlite3.IntegrityError:
					pass
				i += 1
				db.commit()
			while "Active Routes" not in results[i]:
				i += 1
			i += 2
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()	
				c.execute('''CREATE TABLE v4_route_list (ComputerName TEXT, ipAddr text, RouteType TEXT, NetworkDestination text, Netmask text, Gateway text, Interface text, Metric text, unique (ComputerName, ipAddr, NetworkDestination, Interface, Metric))''')
			except sqlite3.OperationalError:
				pass
			while "===" not in results[i]:
				resultsList = results[i].split()
				routeData = (computerName, ipAddr, "Active", resultsList[0], resultsList[1], resultsList[2], resultsList[3], resultsList[4])
				try:
					c.execute('INSERT INTO v4_route_list VALUES (?,?,?,?,?,?,?,?)', routeData)
				except sqlite3.IntegrityError:
					pass
				i += 1
			db.commit()
			i += 2
			if "None" not in results[i]:
				i += 1
				while "===" not in results[i]:
					resultsList = results[i].split()
					routeData = (computerName, ipAddr, "Persistent", resultsList[0], resultsList[1], resultsList[2], "", resultsList[3])
					try:
						c.execute('INSERT INTO v4_route_list VALUES (?,?,?,?,?,?,?,?)', routeData)
					except sqlite3.IntegrityError:
						pass
					i += 1
				db.commit()
				i += 1
			while "===" not in results[i]:
				i += 1
			i += 3
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()	
				c.execute('''CREATE TABLE v6_route_list (ComputerName TEXT, ipAddr text, RouteType TEXT, Interface text, Metric text, NetworkDestination text, Gateway text, unique (ComputerName, ipAddr, NetworkDestination, Interface, Metric))''')
			except sqlite3.OperationalError:
				pass
			while "===" not in results[i]:
				resultsList = results[i].split()
				if len(resultsList) < 4:
					i += 1
					resultsList += results[i].strip().split()
				routeData = (computerName, ipAddr, "Active", resultsList[0], resultsList[1], resultsList[2], resultsList[3])
				try:
					c.execute('INSERT INTO v6_route_list VALUES (?,?,?,?,?,?,?)', routeData)
				except sqlite3.IntegrityError:
					pass
				i += 1
			db.commit()
			i += 2
			if "None" not in results[i]:
				i += 1
				while "===" not in results[i]:
					print results[i]
					resultsList = results[i].split()
					if len(resultsList) < 4:
						i += 1
						resultsList += results[i].strip().split()
					routeData = (computerName, ipAddr, "Persistent", resultsList[0], resultsList[1], resultsList[2], resultsList[3])
					try:
						c.execute('INSERT INTO v6_route_list VALUES (?,?,?,?,?,?,?)', routeData)
					except sqlite3.IntegrityError:
						pass
					i += 1
			db.commit()
			db.close()
		if self.stout:
			while j < len(results):
				j += 1
				
	def arp(self):
		global computerName
		results = self.psexec("arp -a")
		i = 0
		
		interface = ""
		interfaceNum = ""
		
		header = True
		
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE arp_data (ComputerName TEXT, ipAddr text, InterfaceAddr text, InterfaceNum text, Address text, MAC text, Type text, unique (ComputerName, ipAddr, InterfaceAddr, Address))''')
			except sqlite3.OperationalError:
				pass
				
		for line in results:
			if "Interface" in line:
				interface = line.split()[1]
				interfaceNum = line.split()[3]
				header = False
				continue
			if header:
				continue
			if "Internet" not in line and len(line) > 4:
				if self.database != "":
					splitLine = line.split()
					arpData = (computerName, ipAddr, interface, interfaceNum, splitLine[0], splitLine[1], splitLine[2])
					try:
						c.execute('INSERT INTO arp_data VALUES (?,?,?,?,?,?,?)', arpData)
					except sqlite3.IntegrityError:
						pass
				if self.stout:
					print interface + ' ' + interfaceNum + ' ' + line
				 
		if self.database != "":
			db.commit()
			db.close()
				
	def wireless(self):
		global computerName
		results = self.psexec("netsh wlan show profiles")
		i = 0
		header = True
		dash = True
		
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE wireless_profiles (ComputerName TEXT, ipAddr text, Type text, Name text, unique (ComputerName, ipAddr, Type, Name))''')
			except sqlite3.OperationalError:
				pass
		
		for line in results:
			if "User profiles" in line:
				header=False
				continue
			if "----" in line:
				dash = False
				continue
			if header or dash or len(line)<3:
				continue
			if self.database != "":
				splitLine = line.strip().split(':')
				wirelessData = (computerName, ipAddr, splitLine[0].strip(), splitLine[1].strip())
				try:
					c.execute('INSERT INTO wireless_profiles VALUES (?,?,?,?)', wirelessData)
				except sqlite3.IntegrityError:
					pass
				if self.stout:
					print line
		if self.database != "":
			db.commit()
			db.close()

				
