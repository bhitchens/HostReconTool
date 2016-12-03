import wmi, sqlite3, sys, math, netaddr, socket

class WMIConnection:
	
	ipAddr = ""
	database = ""
	
	def __init__(self, remote):
		self.remote = remote
		self.w = None
		global ipAddr
		if remote != "":			
			ipAddr = remote
		else:
			ipAddr = socket.gethostbyname(socket.gethostname())
		
	def connect(self, namespace):
		if self.remote != "":
			self.w = wmi.WMI(self.remote, namespace=mNamespace)
		self.w = wmi.WMI(namespace=mNamespace)

	def connect(self):
		elif self.remote != "":
			self.w = wmi.WMI(self.remote)
		self.w = wmi.WMI()
	
	#use eval to access each attribute under a try/except paradigm	
	def check(self, obj, attrib):
		try:
			return str(eval("obj." + attrib))
		except AttributeError:
			return "NO RESULT"

		
	def sysData(self):
		try:
			db = sqlite3.connect(self.database)
			c = db.cursor()
			c.execute('''CREATE TABLE sys_data (IpAddr TEXT, AdminPasswordStatus TEXT, AutomaticManagedPagefile TEXT, AutomaticResetBootOption TEXT, AutomaticResetCapability TEXT, BootROMSupported TEXT, BootStatus TEXT, BootupState TEXT, Caption TEXT, ChassisBootupState TEXT, ChassisSKUNumber TEXT, CreationClassName TEXT, CurrentTimeZone TEXT, Description TEXT, DNSHostName TEXT, Domain TEXT, DomainRole TEXT, EnableDaylightSavingsTime TEXT, FrontPanelResetStatus TEXT, HypervisorPresent TEXT, InfraredSupported TEXT, KeyboardPasswordStatus TEXT, Manufacturer text, Model text, Name text, NetworkServerModeEnabled text, NumberOfLogicalProcessors text, NumberOfProcessors text, OEMArray text, PartOfDomain text, PauseAfterReset text, PCSystemType text, PCSystemTypeEx text, PowerOnPasswordStatus text, PowerState text, PowerSupplyState text, PrimaryOwnerName text, ResetCapability text, ResetCount text, ResetLimit text, Roles text, Status text, SystemFamily text, SystemSKUNumber text, SystemType text, ThermalState text, TotalPhysicalMemory text, UserName text, WakeUpType text, Workgroup text, unique(Domain,Name))''')
		except sqlite3.OperationalError:
			pass	
		try:
			sys = self.w.Win32_ComputerSystem()[0]
			print self.check(sys, "OEMArray")
			systemData = (ipAddr, self.check(sys, "AdminPasswordStatus"), self.check(sys, "AutomaticManagedPagefile"), self.check(sys, "AutomaticResetBootOption"), self.check(sys, "AutomaticResetCapability"), self.check(sys, "BootROMSupported"), self.check(sys, "BootStatus"), self.check(sys, "BootupState"), self.check(sys, "Caption"), self.check(sys, "ChassisBootupState"), self.check(sys, "ChassisSKUNumber"), self.check(sys, "CreationClassName"), self.check(sys, "CurrentTimeZone"), self.check(sys, "Description"), self.check(sys, "DNSHostName"), self.check(sys, "Domain"), self.check(sys, "DomainRole"), self.check(sys, "EnableDaylightSavingsTime"), self.check(sys, "FrontPanelResetStatus"), self.check(sys, "HypervisorPresent"), self.check(sys, "InfraredSupported"), self.check(sys, "KeyboardPasswordStatus"), self.check(sys, "Manufacturer"), self.check(sys, "Model"), self.check(sys, "Name"), self.check(sys, "NetworkServerModeEnabled"), self.check(sys, "NumberOfLogicalProcessors"), self.check(sys, "NumberOfProcessors"), self.check(sys, "OEMArray"), self.check(sys, "PartOfDomain"), self.check(sys, "PauseAfterReset"), self.check(sys, "PCSystemType"), self.check(sys, "PCSystemTypeEx"), self.check(sys, "PowerOnPasswordStatus"), self.check(sys, "PowerState"), self.check(sys, "PowerSupplyState"), self.check(sys, "PrimaryOwnerName"), self.check(sys, "ResetCapability"), self.check(sys, "ResetCount"), self.check(sys, "ResetLimit"), self.check(sys, "Roles"), self.check(sys, "Status"), self.check(sys, "SystemFamily"), self.check(sys, "SystemSKUNumber"), self.check(sys, "SystemType"), self.check(sys, "ThermalState"), self.check(sys, "TotalPhysicalMemory"), self.check(sys, "UserName"), self.check(sys, "WakeUpType"), self.check(sys, "Workgroup"))
			c.execute('INSERT INTO sys_data VALUES (?, ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', systemData)	
			db.commit()
			db.close()
		except sqlite3.IntegrityError:
			pass
		return
	
	def userData(self):		
		try:
			db = sqlite3.connect(self.database)
			c = db.cursor()
			c.execute('''CREATE TABLE user_data (ipAddr text, AccountType text, Caption text, Description text, Disabled text, Domain text, FullName text, LocalAccount text, Lockout text, Name text, PasswordChangeable text, PasswordExpires text, PasswordRequired text, SID text, SIDType text, Status text, unique (ipAddr, SID))''')
		except sqlite3.OperationalError:
			pass	
		try:
			for account in self.w.Win32_UserAccount():
				accountData = (ipAddr, self.check(account, "AccountType"), self.check(account, "Caption"), self.check(account, "Description"), self.check(account, "Disabled"), self.check(account, "Domain"), self.check(account, "FullName"), self.check(account, "LocalAccount"), self.check(account, "Lockout"), self.check(account, "Name"), self.check(account, "PasswordChangeable"), self.check(account, "PasswordExpires"), self.check(account, "PasswordRequired"), self.check(account, "SID"), self.check(account, "SIDType"), self.check(account, "Status"))
				c.execute('INSERT INTO user_data VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', accountData)	
			db.commit()
			db.close()
		except sqlite3.IntegrityError:
			pass		
		return

	def netLogin(self):		
		try:
			db = sqlite3.connect(self.database)
			c = db.cursor()
			c.execute('''CREATE TABLE net_login (ipAddr text, Caption text, Description text, SettingID text, AccountExpires text, AuthorizationFlags text, BadPasswordCount text, CodePage text, Comment text, CountryCode text, Flags text, FullName text, HomeDirectory text, HomeDirectoryDrive text, LastLogoff text, LastLogon text, LogonHours text, LogonServer text, MaximumStorage text, Name text, NumberOfLogons text, Parameters text, PasswordAge text, PasswordExpires text, PrimaryGroupId text, Privileges text, Profile text, ScriptPath text, UnitsPerWeek text, UserComment text, UserId text, UserType text, Workstations text, unique (ipAddr, Caption))''')
		except sqlite3.OperationalError:
			pass	
		try:
			for login in self.w.Win32_NetworkLoginProfile():
				loginData = (ipAddr, self.check(login, "Caption"), self.check(login, "Description"), self.check(login, "SettingID"), self.check(login, "AccountExpires"), self.check(login, "AuthorizationFlags"), self.check(login, "BadPasswordCount"), self.check(login, "CodePage"), self.check(login, "Comment"), self.check(login, "CountryCode"), self.check(login, "Flags"), self.check(login, "FullName"), self.check(login, "HomeDirectory"), self.check(login, "HomeDirectoryDrive"), self.check(login, "LastLogoff"), self.check(login, "LastLogon"), self.check(login, "LogonHours"), self.check(login, "LogonServer"), self.check(login, "MaximumStorage"), self.check(login, "Name"), self.check(login, "NumberOfLogons"), self.check(login, "Parameters"), self.check(login, "PasswordAge"), self.check(login, "PasswordExpires"), self.check(login, "PrimaryGroupId"), self.check(login, "Privileges"), self.check(login, "Profile"), self.check(login, "ScriptPath"), self.check(login, "UnitsPerWeek"), self.check(login, "UserComment"), self.check(login, "UserId"), self.check(login, "UserType"), self.check(login, "Workstations"))
				c.execute('INSERT INTO net_login VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', loginData)	
			db.commit()
			db.close()
		except sqlite3.IntegrityError:
			pass		
		return
	
	def groupData(self):		
		db = sqlite3.connect(self.database)
		c = db.cursor()	
		try:	
			c.execute('''CREATE TABLE group_data (ipAddr text, Caption text, Description text, Domain text, LocalAccount text, Name text, SID text, SIDType text, Status text, unique (ipAddr, SID))''')
		except sqlite3.OperationalError:
			pass
		try:
			for group in self.w.Win32_Group():
				groupData = (ipAddr, self.check(group, "Caption"), self.check(group, "Description"), self.check(group, "Domain"), self.check(group, "LocalAccount"), self.check(group, "Name"), self.check(group, "SID"), self.check(group, "SIDType"), self.check(group, "Status"))
				c.execute('INSERT INTO group_data VALUES (?,?,?,?,?,?,?,?,?)', groupData)		
			db.commit()
			db.close()
		except sqlite3.IntegrityError:
			pass
		return	

	def logicalDisks(self):		
		try:
			db = sqlite3.connect(self.database)
			c = db.cursor()
			c.execute('''CREATE TABLE logical_disks (ipAddr text, Access text, Availability text, BlockSize text, Caption text,Compressed text, ConfigManagerErrorCode text,ConfigManagerUserConfig text, CreationClassName text, Description text, DeviceID text, DriveType text,ErrorCleared text, ErrorDescription text, ErrorMethodology text, FileSystem text, FreeSpace text, InstallDate text, LastErrorCode text, MaximumComponentLength text, MediaType text, Name text, NumberOfBlocks text, PNPDeviceID text, PowerManagementSupported text, ProviderName text, Purpose text,QuotasDisabled text,QuotasIncomplete text,QuotasRebuilding text, Size text, Status text, StatusInfo text,SupportsDiskQuotas text,SupportsFileBasedCompression text, SystemCreationClassName text, SystemName text,VolumeDirty text, VolumeName text, VolumeSerialNumber text, unique (ipAddr, Caption))''')
		except sqlite3.OperationalError:
			pass	
		try:
			for disk in self.w.Win32_LogicalDisk():
				diskData = (ipAddr, self.check(disk, "Access"), self.check(disk, "Availability"), self.check(disk, "BlockSize"), self.check(disk, "Caption"), self.check(disk, "Compressed"), self.check(disk, "ConfigManagerErrorCode"), self.check(disk, "ConfigManagerUserConfig"), self.check(disk, "CreationClassName"), self.check(disk, "Description"), self.check(disk, "DeviceID"), self.check(disk, "DriveType"), self.check(disk, "ErrorCleared"), self.check(disk, "ErrorDescription"), self.check(disk, "ErrorMethodology"), self.check(disk, "FileSystem"), self.check(disk, "FreeSpace"), self.check(disk, "InstallDate"), self.check(disk, "LastErrorCode"), self.check(disk, "MaximumComponentLength"), self.check(disk, "MediaType"), self.check(disk, "Name"), self.check(disk, "NumberOfBlocks"), self.check(disk, "PNPDeviceID"), self.check(disk, "PowerManagementSupported"), self.check(disk, "ProviderName"), self.check(disk, "Purpose"), self.check(disk, "QuotasDisabled"), self.check(disk, "QuotasIncomplete"), self.check(disk, "QuotasRebuilding"), self.check(disk, "Size"), self.check(disk, "Status"), self.check(disk, "StatusInfo"), self.check(disk, "SupportsDiskQuotas"), self.check(disk, "SupportsFileBasedCompression"), self.check(disk, "SystemCreationClassName"), self.check(disk, "SystemName"), self.check(disk, "VolumeDirty"), self.check(disk, "VolumeName"), self.check(disk, "VolumeSerialNumber"))
				c.execute('INSERT INTO logical_disks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', diskData)
			db.commit()
			db.close()
		except sqlite3.IntegrityError:
			pass		
		return
		
	def timeZone(self):		
		try:
			db = sqlite3.connect(self.database)
			c = db.cursor()
			c.execute('''CREATE TABLE time_zone (ipAddr text, Caption text, Description text, SettingID text, Bias text, DaylightBias text, DaylightDay text, DaylightDayOfWeek text, DaylightHour text, DaylightMillisecond text, DaylightMinute text, DaylightMonth text, DaylightName text, DaylightSecond text, DaylightYear text, StandardBias text, StandardDay text, StandardDayOfWeek text, StandardHour text, StandardMillisecond text, StandardMinute text, StandardMonth text, StandardName text, StandardSecond text, StandardYear text, unique (ipAddr))''')
		except sqlite3.OperationalError:
			pass	
		try:
			for zone in self.w.Win32_TimeZone():
				zoneData = (ipAddr, self.check(zone, "Caption"), self.check(zone, "Description"), self.check(zone, "SettingID"), self.check(zone, "Bias"), self.check(zone, "DaylightBias"), self.check(zone, "DaylightDay"), self.check(zone, "DaylightDayOfWeek"), self.check(zone, "DaylightHour"), self.check(zone, "DaylightMillisecond"), self.check(zone, "DaylightMinute"), self.check(zone, "DaylightMonth"), self.check(zone, "DaylightName"), self.check(zone, "DaylightSecond"), self.check(zone, "DaylightYear"), self.check(zone, "StandardBias"), self.check(zone, "StandardDay"), self.check(zone, "StandardDayOfWeek"), self.check(zone, "StandardHour"), self.check(zone, "StandardMillisecond"), self.check(zone, "StandardMinute"), self.check(zone, "StandardMonth"), self.check(zone, "StandardName"), self.check(zone, "StandardSecond"), self.check(zone, "StandardYear"))
				c.execute('INSERT INTO time_zone VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', zoneData)	
			db.commit()
			db.close()
		except sqlite3.IntegrityError:
			pass		
		return
		
	def startupPrograms(self):		
		try:
			db = sqlite3.connect(self.database)
			c = db.cursor()
			c.execute('''CREATE TABLE startup_programs (ipAddr text, Caption text, Description text, SettingID text, Command text, Location text, Name text, User text, UserSID, unique (ipAddr, Caption, UserSID))''')
		except sqlite3.OperationalError:
			pass	
		for program in self.w.Win32_StartupCommand():
			try:
				programData = (ipAddr, self.check(program, "Caption"), self.check(program, "Description"), self.check(program, "SettingID"), self.check(program, "Command"), self.check(program, "Location"), self.check(program, "Name"), self.check(program, "User"), self.check(program, "UserSID"))
				c.execute('INSERT INTO startup_programs VALUES (?,?,?,?,?,?,?,?,?)', programData)
			except sqlite3.IntegrityError:
				pass
		db.commit()
		db.close()				
		return	
