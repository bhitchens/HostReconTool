import sqlite3, sys, socket, subprocess, re, os

class PSExecQuery:

	ipAddr = ""
	database = ""
	computerName = ""
	stout = False
	
	def __init__(self, remote, verbose, lock, database):
		self.remote = remote
		self.w = None
		self.verbose = verbose
		self.lock = lock
		global ipAddr
		#if a remote IP has been provided, set the ipAddr global to that IP
		if remote != "":
			ipAddr = str(remote)
		#else set it to the local system's IP
		else:
			ipAddr = socket.gethostbyname(socket.gethostname())
			
	def connectDB(self, cursor):
		self.c = cursor
			
	def setComputerName(self):
		global computerName
		computerName = self.psexec("hostname")[-2]

	def psexec(self, command):
		#TODO: should receive stderr and check for success/failure
		list = ["psexec.exe", "-AcceptEULA", "-nobanner", "\\\\" + str(ipAddr), "-h"] + command.split(" ")
		proc = subprocess.check_output(list, stderr=subprocess.DEVNULL, text=True)
		return proc.split('\n')
		
	def dbInsert(self, name, data):
		self.lock.acquire()
		self.c.execute('INSERT INTO ' + name + ' VALUES (?' + ', ?' * (len(data) - 1) + ')', data)
		self.lock.release()
		
	def dbEntry(self, itemList, uniqueList, name, dataList):
		db = sqlite3.connect(self.database)
		db.text_factory = str
		c = db.cursor()
		self.lock.acquire()
		try:
			#create table
			c.execute('''CREATE TABLE ''' + name + ''' (ComputerName TEXT, ipAddr text,''' + (''' {} text,''' * len(itemList)).format(*itemList) +  '''unique (''' + uniqueList + '''))''')
		except sqlite3.OperationalError:
			pass
		#for each object in the data list
		for data in dataList:
			try:
				#initial values for all table entries
				values = []
				#for each potential element of the object, add it to the values list
				for item in data:
					values.append(item)
				#enter the values into the db
				c.execute('INSERT INTO ' + name + ' VALUES (?' + ', ?' * (len(values) - 1) + ')', values)
			except sqlite3.IntegrityError:
				pass
		db.commit()
		db.close()
		self.lock.release()
		
	def all(self):
		self.ports()
		self.route()
		self.arp()
		self.wireless()
	
	def ports(self):
		global computerName
		results = self.psexec("netstat -anob")
		i = 0
		while "Proto" not in results[i]:
			i += 1
		i += 1
		j = i
		#fixed to run normally
		if self.database != "":
			portsData = []
			while i < len(results) - 1:
				splitLine = results[i].split()
				if len(splitLine) < 3:
					i += 1
				else:
					local = splitLine[1].replace("::", ";;").split(':')
					localIP = ""						
					foreign = splitLine[2].replace("::",";;").split(':')
					i += 1
					owner = ""
					if "TIME_WAIT" not in results[i-1]:
						owner = results[i].strip()
						i += 1
						if len(results[i]) > 1 and results[i].split()[0][0] == '[':
							owner += ' ' + results[i].strip()
							i += 1
					if splitLine[0] == "TCP":
						portsData.append((computerName, ipAddr, splitLine[0], local[0].replace(";;", "::"), local[1], foreign[0].replace(";;", "::"), foreign[1], splitLine[3], splitLine[4], owner))
					else:
						portsData.append((computerName, ipAddr, splitLine[0], local[0].replace(";;", "::"), local[1], foreign[0].replace(";;", "::"), foreign[1], "", splitLine[3], owner))
			itemList = ("Protocol", "LocalIP", "LocalPort", "ForeignIP", "ForeignPort", "State", "PID", "Owner")
			uniqueList = "ComputerName, ipAddr, LocalIP, LocalPort, ForeignIP, ForeignPort"
			self.dbEntry(itemList, uniqueList, "open_ports", portsData)	
		if self.stout:
			for line in results: print(line)
				
	def route(self):
		global computerName
		results = self.psexec("route print")
		i = 0
		while "Interface List" not in results[i]:
			i += 1
		i += 1
		j = i
		
		if self.database != "":
		
			#send interface data to database
			interfaceData = []
			while "===" not in results[i]:
				resultsList = re.sub('\.\.+', ';;', results[i]).split(";;")
				if len(resultsList) == 3:
					interfaceData.append((computerName, ipAddr, resultsList[0], resultsList[1], resultsList[2]))
				else:
					interfaceData.append((computerName, ipAddr, resultsList[0], "", resultsList[1]))				
				i += 1
			itemList = "Interface", "MAC", "Label"
			uniqueList = "ComputerName, ipAddr, Interface"
			self.dbEntry(itemList, uniqueList, "interface_list", interfaceData)
			
			while "Active Routes" not in results[i]:
				i += 1
			i += 2

			#send IPv4 route data to database
			routeData = []
			while "===" not in results[i]:
				resultsList = results[i].split()
				routeData.append((computerName, ipAddr, "Active", resultsList[0], resultsList[1], resultsList[2], resultsList[3], resultsList[4]))
				i += 1
			i += 2
			if "None" not in results[i]:
				i += 1
				while "===" not in results[i]:
					resultsList = results[i].split()
					routeData.append((computerName, ipAddr, "Persistent", resultsList[0], resultsList[1], resultsList[2], "", resultsList[3]))
					i += 1
				i += 1
			itemList = "RouteType", "NetworkDestination", "Netmask", "Gateway", "Interface", "Metric text"
			uniqueList = "ComputerName, ipAddr, NetworkDestination, Interface, Metric"
			self.dbEntry(itemList, uniqueList, "v4_route_list", routeData)
			
			while "===" not in results[i]:
				i += 1
			i += 3
			
			#send IPv6 route data to database
			routeData = []
			while "===" not in results[i]:
				resultsList = results[i].split()
				if len(resultsList) < 4:
					i += 1
					resultsList += results[i].strip().split()
				routeData.append((computerName, ipAddr, "Active", resultsList[0], resultsList[1], resultsList[2], resultsList[3]))
				i += 1
			i += 2
			if "None" not in results[i]:
				i += 1
				while "===" not in results[i]:
					print(results[i])
					resultsList = results[i].split()
					if len(resultsList) < 4:
						i += 1
						resultsList += results[i].strip().split()
					routeData.append((computerName, ipAddr, "Persistent", resultsList[0], resultsList[1], resultsList[2], resultsList[3]))
					i += 1
			itemList = "RouteType", "Interface", "Metric", "NetworkDestination", "Gateway"
			uniqueList = "ComputerName, ipAddr, NetworkDestination, Interface, Metric"
			self.dbEntry(itemList, uniqueList, "v6_route_list", routeData)
		
		#send data to standard out
		if self.stout:
			for line in results:
				print(line)
				
	def arp(self):
		global computerName
		results = self.psexec("arp -a")
		i = 0		
		interface = ""
		interfaceNum = ""		
		header = True		
		if self.database != "":
			arpData = []
			for line in results:
				if "Interface" in line:
					interface = line.split()[1]
					interfaceNum = line.split()[3]
					header = False
					continue
				if header:
					continue
				if "Internet" not in line and len(line) > 4:
					splitLine = line.split()
					arpData.append((computerName, ipAddr, interface, interfaceNum, splitLine[0], splitLine[1], splitLine[2]))
			itemList = "InterfaceAddr", "InterfaceNum", "Address", "MAC", "Type"
			uniqueList = "ComputerName, ipAddr, InterfaceAddr, Address"
			self.dbEntry(itemList, uniqueList, "arp_data", arpData)
		if self.stout:
			for line in results:
				print(line)
				
	def wireless(self):
		global computerName
		results = self.psexec("netsh wlan show profiles")
		i = 0
		header = True
		dash = True		
		if self.database != "":
			wirelessData = []
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
					wirelessData.append((computerName, ipAddr, splitLine[0].strip(), splitLine[1].strip()))
			itemList = "Type", "Name"
			uniqueList = "ComputerName, ipAddr, Type, Name"
			self.dbEntry(itemList, uniqueList, "wireless_profiles", wirelessData)
		if self.stout:
			print(line)