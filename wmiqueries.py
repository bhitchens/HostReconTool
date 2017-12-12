import wmi, sqlite3, sys, math, netaddr, socket

class WMIConnection:
	
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
		
	#make a WMI connection with a non-standard namespace
	def connect(self, namespace):
		if self.password != "":
			self.w = wmi.WMI(self.remote, user=self.user, password=self.password, namespace=mNamespace)
		elif self.user != "":
			self.w = wmi.WMI(self.remote, user=self.user, namespace=mNamespace)
		elif self.remote != "":
			self.w = wmi.WMI(self.remote, namespace=mNamespace)
		else:
			self.w = wmi.WMI(namespace=mNamespace)

	#make a WMI connection with the standard namespace
	def connect(self):
		if self.password != "":
			self.w = wmi.WMI(self.remote, user=self.user, password=self.password)
		elif self.user != "":
			self.w = wmi.WMI(self.remote, user=self.user)
		elif self.remote != "":
			self.w = wmi.WMI(self.remote)
		else:
			self.w = wmi.WMI()
	
	#use eval to access each attribute under a try/except paradigm	
	def check(self, obj, attrib):
		try:
			return str(eval("obj." + attrib))
		except AttributeError:
			return "NO RESULT"
			
	def getComputerName(self):
		return computerName
			
	def all(self):
		self.sysData()
		self.userData()
		self.netLogin()
		self.groupData()
		self.logicalDisks()
		self.timeZone()
		self.startupPrograms()
		self.userProfiles()
		self.networkAdapters()
		self.processes()
		self.services()
		self.shares()
		self.physicalDisks()
		self.physicalMemory()

	#comments on this method apply to the other WMI methods
	def sysData(self):
		#get the WMI data
		sys = self.w.Win32_ComputerSystem()[0]
		#if a db has been provided
		if self.database != "":
			try:
				#connect to the db
				db = sqlite3.connect(self.database)
				#create a cursor
				c = db.cursor()
				#get the computer name
				global computerName
				computerName = sys.Name
				#attempt to create the table; will fail if the table is already created
				c.execute('''CREATE TABLE sys_data (IpAddr TEXT, AdminPasswordStatus TEXT, AutomaticManagedPagefile TEXT, AutomaticResetBootOption TEXT, AutomaticResetCapability TEXT, BootROMSupported TEXT, BootStatus TEXT, BootupState TEXT, Caption TEXT, ChassisBootupState TEXT, ChassisSKUNumber TEXT, CreationClassName TEXT, CurrentTimeZone TEXT, Description TEXT, DNSHostName TEXT, Domain TEXT, DomainRole TEXT, EnableDaylightSavingsTime TEXT, FrontPanelResetStatus TEXT, HypervisorPresent TEXT, InfraredSupported TEXT, KeyboardPasswordStatus TEXT, Manufacturer text, Model text, Name text, NetworkServerModeEnabled text, NumberOfLogicalProcessors text, NumberOfProcessors text, OEMArray text, PartOfDomain text, PauseAfterReset text, PCSystemType text, PCSystemTypeEx text, PowerOnPasswordStatus text, PowerState text, PowerSupplyState text, PrimaryOwnerName text, ResetCapability text, ResetCount text, ResetLimit text, Roles text, Status text, SystemFamily text, SystemSKUNumber text, SystemType text, ThermalState text, TotalPhysicalMemory text, UserName text, WakeUpType text, Workgroup text, unique(Domain,Name))''')
			except sqlite3.OperationalError:
				#this error just means the table was already created; this is normal and fine
				pass	
			try:
				#put the data in a string array, using the check method to process the attributes
				systemData = (ipAddr, self.check(sys, "AdminPasswordStatus"), self.check(sys, "AutomaticManagedPagefile"), self.check(sys, "AutomaticResetBootOption"), self.check(sys, "AutomaticResetCapability"), self.check(sys, "BootROMSupported"), self.check(sys, "BootStatus"), self.check(sys, "BootupState"), self.check(sys, "Caption"), self.check(sys, "ChassisBootupState"), self.check(sys, "ChassisSKUNumber"), self.check(sys, "CreationClassName"), self.check(sys, "CurrentTimeZone"), self.check(sys, "Description"), self.check(sys, "DNSHostName"), self.check(sys, "Domain"), self.check(sys, "DomainRole"), self.check(sys, "EnableDaylightSavingsTime"), self.check(sys, "FrontPanelResetStatus"), self.check(sys, "HypervisorPresent"), self.check(sys, "InfraredSupported"), self.check(sys, "KeyboardPasswordStatus"), self.check(sys, "Manufacturer"), self.check(sys, "Model"), self.check(sys, "Name"), self.check(sys, "NetworkServerModeEnabled"), self.check(sys, "NumberOfLogicalProcessors"), self.check(sys, "NumberOfProcessors"), self.check(sys, "OEMArray"), self.check(sys, "PartOfDomain"), self.check(sys, "PauseAfterReset"), self.check(sys, "PCSystemType"), self.check(sys, "PCSystemTypeEx"), self.check(sys, "PowerOnPasswordStatus"), self.check(sys, "PowerState"), self.check(sys, "PowerSupplyState"), self.check(sys, "PrimaryOwnerName"), self.check(sys, "ResetCapability"), self.check(sys, "ResetCount"), self.check(sys, "ResetLimit"), self.check(sys, "Roles"), self.check(sys, "Status"), self.check(sys, "SystemFamily"), self.check(sys, "SystemSKUNumber"), self.check(sys, "SystemType"), self.check(sys, "ThermalState"), self.check(sys, "TotalPhysicalMemory"), self.check(sys, "UserName"), self.check(sys, "WakeUpType"), self.check(sys, "Workgroup"))
				#insert the values into the table
				c.execute('INSERT INTO sys_data VALUES (?, ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', systemData)	
				#commit the db change
				db.commit()
				#close the db
				db.close()
			except sqlite3.IntegrityError:
				pass
		#if standard out is selected, print the WMI data to standard out
		if self.stout:
			print sys
		return
	
	def userData(self):
		accounts = self.w.Win32_UserAccount()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE user_data (ComputerName TEXT, ipAddr text, AccountType text, Caption text, Description text, Disabled text, Domain text, FullName text, LocalAccount text, Lockout text, Name text, PasswordChangeable text, PasswordExpires text, PasswordRequired text, SID text, SIDType text, Status text, unique (ComputerName,ipAddr, SID))''')
			except sqlite3.OperationalError:
				pass	
			try:
				for account in accounts:
					accountData = (computerName, ipAddr, self.check(account, "AccountType"), self.check(account, "Caption"), self.check(account, "Description"), self.check(account, "Disabled"), self.check(account, "Domain"), self.check(account, "FullName"), self.check(account, "LocalAccount"), self.check(account, "Lockout"), self.check(account, "Name"), self.check(account, "PasswordChangeable"), self.check(account, "PasswordExpires"), self.check(account, "PasswordRequired"), self.check(account, "SID"), self.check(account, "SIDType"), self.check(account, "Status"))
					c.execute('INSERT INTO user_data VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', accountData)	
				db.commit()
				db.close()
			except sqlite3.IntegrityError:
				pass
		if self.stout:
			for account in accounts:
				print account
		return

	def netLogin(self):
		logins = self.w.Win32_NetworkLoginProfile()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE net_login (ComputerName TEXT, ipAddr text, Caption text, Description text, SettingID text, AccountExpires text, AuthorizationFlags text, BadPasswordCount text, CodePage text, Comment text, CountryCode text, Flags text, FullName text, HomeDirectory text, HomeDirectoryDrive text, LastLogoff text, LastLogon text, LogonHours text, LogonServer text, MaximumStorage text, Name text, NumberOfLogons text, Parameters text, PasswordAge text, PasswordExpires text, PrimaryGroupId text, Privileges text, Profile text, ScriptPath text, UnitsPerWeek text, UserComment text, UserId text, UserType text, Workstations text, unique (ComputerName,ipAddr, Caption))''')
			except sqlite3.OperationalError:
				pass	
			try:
				for login in logins:
					loginData = (computerName, ipAddr, self.check(login, "Caption"), self.check(login, "Description"), self.check(login, "SettingID"), self.check(login, "AccountExpires"), self.check(login, "AuthorizationFlags"), self.check(login, "BadPasswordCount"), self.check(login, "CodePage"), self.check(login, "Comment"), self.check(login, "CountryCode"), self.check(login, "Flags"), self.check(login, "FullName"), self.check(login, "HomeDirectory"), self.check(login, "HomeDirectoryDrive"), self.check(login, "LastLogoff"), self.check(login, "LastLogon"), self.check(login, "LogonHours"), self.check(login, "LogonServer"), self.check(login, "MaximumStorage"), self.check(login, "Name"), self.check(login, "NumberOfLogons"), self.check(login, "Parameters"), self.check(login, "PasswordAge"), self.check(login, "PasswordExpires"), self.check(login, "PrimaryGroupId"), self.check(login, "Privileges"), self.check(login, "Profile"), self.check(login, "ScriptPath"), self.check(login, "UnitsPerWeek"), self.check(login, "UserComment"), self.check(login, "UserId"), self.check(login, "UserType"), self.check(login, "Workstations"))
					c.execute('INSERT INTO net_login VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', loginData)	
				db.commit()
				db.close()
			except sqlite3.IntegrityError:
				pass		
		if self.stout:
			for login in logins:
				print login
		return
	
	def groupData(self):
		groups = self.w.Win32_Group()
		if self.database != "":
			db = sqlite3.connect(self.database)
			c = db.cursor()	
			try:	
				c.execute('''CREATE TABLE group_data (ComputerName TEXT, ipAddr text, Caption text, Description text, Domain text, LocalAccount text, Name text, SID text, SIDType text, Status text, unique (ComputerName, ipAddr, SID))''')
			except sqlite3.OperationalError:
				pass
			try:
				for group in groups:
					groupData = (computerName, ipAddr, self.check(group, "Caption"), self.check(group, "Description"), self.check(group, "Domain"), self.check(group, "LocalAccount"), self.check(group, "Name"), self.check(group, "SID"), self.check(group, "SIDType"), self.check(group, "Status"))
					c.execute('INSERT INTO group_data VALUES (?,?,?,?,?,?,?,?,?,?)', groupData)		
				db.commit()
				db.close()
			except sqlite3.IntegrityError:
				pass
		if self.stout:
			for group in groups:
				print group
		return	

	def logicalDisks(self):		
		disks = self.w.Win32_LogicalDisk()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE logical_disks (ComputerName TEXT, ipAddr text, Access text, Availability text, BlockSize text, Caption text,Compressed text, ConfigManagerErrorCode text,ConfigManagerUserConfig text, CreationClassName text, Description text, DeviceID text, DriveType text,ErrorCleared text, ErrorDescription text, ErrorMethodology text, FileSystem text, FreeSpace text, InstallDate text, LastErrorCode text, MaximumComponentLength text, MediaType text, Name text, NumberOfBlocks text, PNPDeviceID text, PowerManagementSupported text, ProviderName text, Purpose text,QuotasDisabled text,QuotasIncomplete text,QuotasRebuilding text, Size text, Status text, StatusInfo text,SupportsDiskQuotas text,SupportsFileBasedCompression text, SystemCreationClassName text, SystemName text,VolumeDirty text, VolumeName text, VolumeSerialNumber text, unique (ComputerName, ipAddr, Caption))''')
			except sqlite3.OperationalError:
				pass	
			try:
				for disk in disks:
					diskData = (computerName, ipAddr, self.check(disk, "Access"), self.check(disk, "Availability"), self.check(disk, "BlockSize"), self.check(disk, "Caption"), self.check(disk, "Compressed"), self.check(disk, "ConfigManagerErrorCode"), self.check(disk, "ConfigManagerUserConfig"), self.check(disk, "CreationClassName"), self.check(disk, "Description"), self.check(disk, "DeviceID"), self.check(disk, "DriveType"), self.check(disk, "ErrorCleared"), self.check(disk, "ErrorDescription"), self.check(disk, "ErrorMethodology"), self.check(disk, "FileSystem"), self.check(disk, "FreeSpace"), self.check(disk, "InstallDate"), self.check(disk, "LastErrorCode"), self.check(disk, "MaximumComponentLength"), self.check(disk, "MediaType"), self.check(disk, "Name"), self.check(disk, "NumberOfBlocks"), self.check(disk, "PNPDeviceID"), self.check(disk, "PowerManagementSupported"), self.check(disk, "ProviderName"), self.check(disk, "Purpose"), self.check(disk, "QuotasDisabled"), self.check(disk, "QuotasIncomplete"), self.check(disk, "QuotasRebuilding"), self.check(disk, "Size"), self.check(disk, "Status"), self.check(disk, "StatusInfo"), self.check(disk, "SupportsDiskQuotas"), self.check(disk, "SupportsFileBasedCompression"), self.check(disk, "SystemCreationClassName"), self.check(disk, "SystemName"), self.check(disk, "VolumeDirty"), self.check(disk, "VolumeName"), self.check(disk, "VolumeSerialNumber"))
					c.execute('INSERT INTO logical_disks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', diskData)
				db.commit()
				db.close()
			except sqlite3.IntegrityError:
				pass		
		if self.stout:
			for disk in disks:
				print disk
		return
		
	def timeZone(self):
		zones = self.w.Win32_TimeZone()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE time_zone (ComputerName TEXT, ipAddr text, Caption text, Description text, SettingID text, Bias text, DaylightBias text, DaylightDay text, DaylightDayOfWeek text, DaylightHour text, DaylightMillisecond text, DaylightMinute text, DaylightMonth text, DaylightName text, DaylightSecond text, DaylightYear text, StandardBias text, StandardDay text, StandardDayOfWeek text, StandardHour text, StandardMillisecond text, StandardMinute text, StandardMonth text, StandardName text, StandardSecond text, StandardYear text, unique (ComputerName, ipAddr))''')
			except sqlite3.OperationalError:
				pass	
			try:
				for zone in zones:
					zoneData = (computerName, ipAddr, self.check(zone, "Caption"), self.check(zone, "Description"), self.check(zone, "SettingID"), self.check(zone, "Bias"), self.check(zone, "DaylightBias"), self.check(zone, "DaylightDay"), self.check(zone, "DaylightDayOfWeek"), self.check(zone, "DaylightHour"), self.check(zone, "DaylightMillisecond"), self.check(zone, "DaylightMinute"), self.check(zone, "DaylightMonth"), self.check(zone, "DaylightName"), self.check(zone, "DaylightSecond"), self.check(zone, "DaylightYear"), self.check(zone, "StandardBias"), self.check(zone, "StandardDay"), self.check(zone, "StandardDayOfWeek"), self.check(zone, "StandardHour"), self.check(zone, "StandardMillisecond"), self.check(zone, "StandardMinute"), self.check(zone, "StandardMonth"), self.check(zone, "StandardName"), self.check(zone, "StandardSecond"), self.check(zone, "StandardYear"))
					c.execute('INSERT INTO time_zone VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', zoneData)	
				db.commit()
				db.close()
			except sqlite3.IntegrityError:
				pass
		if self.stout:
			for zone in zones:
				print zone
		return
		
	def startupPrograms(self):
		programs = self.w.Win32_StartupCommand()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE startup_programs (ComputerName TEXT, ipAddr text, Caption text, Description text, SettingID text, Command text, Location text, Name text, User text, UserSID text, unique (ComputerName, ipAddr, Caption, UserSID))''')
			except sqlite3.OperationalError:
				pass
			for program in programs:
				try:
					programData = (computerName, ipAddr, self.check(program, "Caption"), self.check(program, "Description"), self.check(program, "SettingID"), self.check(program, "Command"), self.check(program, "Location"), self.check(program, "Name"), self.check(program, "User"), self.check(program, "UserSID"))
					c.execute('INSERT INTO startup_programs VALUES (?,?,?,?,?,?,?,?,?,?)', programData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for program in programs:
				print program
		return

	def userProfiles(self):
		profiles = self.w.Win32_UserProfile()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE user_profiles (ComputerName TEXT, ipAddr text, SID text, LocalPath text, Loaded text, refCount text, Special text, RoamingConfigured text, RoamingPath text, RoamingPreference text, Status text, LastUseTime text, LastDownloadTime text, LastUploadTime text, HealthStatus text, LastAttemptedProfileDownloadTime text, LastAttemptedProfileUploadTime text, LastBackgroundRegistryUploadTime text, AppDataRoaming text, Desktop text, StartMenu text, Documents text, Pictures text, Music text, Videos text, Favorites text, Contacts text, Downloads text, Links text, Searches text, SavedGames text, unique (ComputerName, ipAddr, SID, LastUseTime))''')
			except sqlite3.OperationalError:
				pass
			for profile in profiles:
				try:
					profileData = (computerName, ipAddr, self.check(profile, "SID"), self.check(profile, "LocalPath"), self.check(profile, "Loaded"), self.check(profile, "refCount"), self.check(profile, "Special"), self.check(profile, "RoamingConfigured"), self.check(profile, "RoamingPath"), self.check(profile, "RoamingPreference"), self.check(profile, "Status"), self.check(profile, "LastUseTime"), self.check(profile, "LastDownloadTime"), self.check(profile, "LastUploadTime"), self.check(profile, "HealthStatus"), self.check(profile, "LastAttemptedProfileDownloadTime"), self.check(profile, "LastAttemptedProfileUploadTime"), self.check(profile, "LastBackgroundRegistryUploadTime"), self.check(profile, "AppDataRoaming"), self.check(profile, "Desktop"), self.check(profile, "StartMenu"), self.check(profile, "Documents"), self.check(profile, "Pictures"), self.check(profile, "Music"), self.check(profile, "Videos"), self.check(profile, "Favorites"), self.check(profile, "Contacts"), self.check(profile, "Downloads"), self.check(profile, "Links"), self.check(profile, "Searches"), self.check(profile, "SavedGames"))
					c.execute('INSERT INTO user_profiles VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', profileData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for profile in profiles:
				print profile
		return		
		
	def networkAdapters(self):
		adapters = self.w.Win32_NetworkAdapterConfiguration()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE network_adapters (ComputerName TEXT, ipAddr text, Caption text, Description text, SettingID text, ArpAlwaysSourceRoute text, ArpUseEtherSNAP text, DatabasePath text, DeadGWDetectEnabled text, DefaultIPGateway text, DefaultTOS text, DefaultTTL text, DHCPEnabled text, DHCPLeaseExpires text, DHCPLeaseObtained text, DHCPServer text, DNSDomain text, DNSDomainSuffixSearchOrder text, DNSEnabledForWINSResolution text, DNSHostName text, DNSServerSearchOrder text, DomainDNSRegistrationEnabled text, ForwardBufferMemory text, FullDNSRegistrationEnabled text, GatewayCostMetric text, IGMPLevel text, _Index text, InterfaceIndex text, IPAddress text, IPConnectionMetric text, IPEnabled text, IPFilterSecurityEnabled text, IPPortSecurityEnabled text, IPSecPermitIPProtocols text, IPSecPermitTCPPorts text, IPSecPermitUDPPorts text, IPSubnet text, IPUseZeroBroadcast text, IPXAddress text, IPXEnabled text, IPXFrameType text, IPXMediaType text, IPXNetworkNumber text, IPXVirtualNetNumber text, KeepAliveInterval text, KeepAliveTime text, MACAddress text, MTU text, NumForwardPackets text, PMTUBHDetectEnabled text, PMTUDiscoveryEnabled text, ServiceName text, TcpipNetbiosOptions text, TcpMaxConnectRetransmissions text, TcpMaxDataRetransmissions text, TcpNumConnections text, TcpUseRFC1122UrgentPointer text, TcpWindowSize text, WINSEnableLMHostsLookup text, WINSHostLookupFile text, WINSPrimaryServer text, WINSScopeID text, WINSSecondaryServer text, unique (ComputerName, ipAddr, MACAddress))''')
			except sqlite3.OperationalError:
				pass
			for adapter in adapters:
				try:
					adapterData = (computerName, ipAddr, self.check(adapter, "Caption"), self.check(adapter, "Description"), self.check(adapter, "SettingID"), self.check(adapter, "ArpAlwaysSourceRoute"), self.check(adapter, "ArpUseEtherSNAP"), self.check(adapter, "DatabasePath"), self.check(adapter, "DeadGWDetectEnabled"), self.check(adapter, "DefaultIPGateway"), self.check(adapter, "DefaultTOS"), self.check(adapter, "DefaultTTL"), self.check(adapter, "DHCPEnabled"), self.check(adapter, "DHCPLeaseExpires"), self.check(adapter, "DHCPLeaseObtained"), self.check(adapter, "DHCPServer"), self.check(adapter, "DNSDomain"), self.check(adapter, "DNSDomainSuffixSearchOrder"), self.check(adapter, "DNSEnabledForWINSResolution"), self.check(adapter, "DNSHostName"), self.check(adapter, "DNSServerSearchOrder"), self.check(adapter, "DomainDNSRegistrationEnabled"), self.check(adapter, "ForwardBufferMemory"), self.check(adapter, "FullDNSRegistrationEnabled"), self.check(adapter, "GatewayCostMetric"), self.check(adapter, "IGMPLevel"), self.check(adapter, "Index"), self.check(adapter, "InterfaceIndex"), self.check(adapter, "IPAddress"), self.check(adapter, "IPConnectionMetric"), self.check(adapter, "IPEnabled"), self.check(adapter, "IPFilterSecurityEnabled"), self.check(adapter, "IPPortSecurityEnabled"), self.check(adapter, "IPSecPermitIPProtocols"), self.check(adapter, "IPSecPermitTCPPorts"), self.check(adapter, "IPSecPermitUDPPorts"), self.check(adapter, "IPSubnet"), self.check(adapter, "IPUseZeroBroadcast"), self.check(adapter, "IPXAddress"), self.check(adapter, "IPXEnabled"), self.check(adapter, "IPXFrameType"), self.check(adapter, "IPXMediaType"), self.check(adapter, "IPXNetworkNumber"), self.check(adapter, "IPXVirtualNetNumber"), self.check(adapter, "KeepAliveInterval"), self.check(adapter, "KeepAliveTime"), self.check(adapter, "MACAddress"), self.check(adapter, "MTU"), self.check(adapter, "NumForwardPackets"), self.check(adapter, "PMTUBHDetectEnabled"), self.check(adapter, "PMTUDiscoveryEnabled"), self.check(adapter, "ServiceName"), self.check(adapter, "TcpipNetbiosOptions"), self.check(adapter, "TcpMaxConnectRetransmissions"), self.check(adapter, "TcpMaxDataRetransmissions"), self.check(adapter, "TcpNumConnections"), self.check(adapter, "TcpUseRFC1122UrgentPointer"), self.check(adapter, "TcpWindowSize"), self.check(adapter, "WINSEnableLMHostsLookup"), self.check(adapter, "WINSHostLookupFile"), self.check(adapter, "WINSPrimaryServer"), self.check(adapter, "WINSScopeID"), self.check(adapter, "WINSSecondaryServer"))
					c.execute('INSERT INTO network_adapters VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', adapterData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for adapter in adapters:
				print adapter
		return

	def processes(self):
		processes = self.w.win32_process()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				c = db.cursor()
				c.execute('''CREATE TABLE processes (ComputerName TEXT, ipAddr text, CreationClassName text, Caption text, CommandLine text, CreationDate text, CSCreationClassName text, CSName text, Description text, ExecutablePath text, ExecutionState text, Handle text, HandleCount text, InstallDate text, KernelModeTime text, MaximumWorkingSetSize text, MinimumWorkingSetSize text, Name text, OSCreationClassName text, OSName text, OtherOperationCount text, OtherTransferCount text, PageFaults text, PageFileUsage text, ParentProcessId text, PeakPageFileUsage text, PeakVirtualSize text, PeakWorkingSetSize text, Priority text, PrivatePageCount text, ProcessId text, QuotaNonPagedPoolUsage text, QuotaPagedPoolUsage text, QuotaPeakNonPagedPoolUsage text, QuotaPeakPagedPoolUsage text, ReadOperationCount text, ReadTransferCount text, SessionId text, Status text, TerminationDate text, ThreadCount text, UserModeTime text, VirtualSize text, WindowsVersion text, WorkingSetSize text, WriteOperationCount text, WriteTransferCount text, unique (ComputerName, ipAddr, ProcessId))''')
			except sqlite3.OperationalError:
				pass
			for process in processes:
				try:
					processData = (computerName, ipAddr, self.check(process, "CreationClassName"), self.check(process, "Caption"), self.check(process, "CommandLine"), self.check(process, "CreationDate"), self.check(process, "CSCreationClassName"), self.check(process, "CSName"), self.check(process, "Description"), self.check(process, "ExecutablePath"), self.check(process, "ExecutionState"), self.check(process, "Handle"), self.check(process, "HandleCount"), self.check(process, "InstallDate"), self.check(process, "KernelModeTime"), self.check(process, "MaximumWorkingSetSize"), self.check(process, "MinimumWorkingSetSize"), self.check(process, "Name"), self.check(process, "OSCreationClassName"), self.check(process, "OSName"), self.check(process, "OtherOperationCount"), self.check(process, "OtherTransferCount"), self.check(process, "PageFaults"), self.check(process, "PageFileUsage"), self.check(process, "ParentProcessId"), self.check(process, "PeakPageFileUsage"), self.check(process, "PeakVirtualSize"), self.check(process, "PeakWorkingSetSize"), self.check(process, "Priority"), self.check(process, "PrivatePageCount"), self.check(process, "ProcessId"), self.check(process, "QuotaNonPagedPoolUsage"), self.check(process, "QuotaPagedPoolUsage"), self.check(process, "QuotaPeakNonPagedPoolUsage"), self.check(process, "QuotaPeakPagedPoolUsage"), self.check(process, "ReadOperationCount"), self.check(process, "ReadTransferCount"), self.check(process, "SessionId"), self.check(process, "Status"), self.check(process, "TerminationDate"), self.check(process, "ThreadCount"), self.check(process, "UserModeTime"), self.check(process, "VirtualSize"), self.check(process, "WindowsVersion"), self.check(process, "WorkingSetSize"), self.check(process, "WriteOperationCount"), self.check(process, "WriteTransferCount"))
					c.execute('INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', processData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for process in processes:
				print process
		return
		
	def services(self):
		services = self.w.win32_Service()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				db.text_factory = str
				c = db.cursor()
				c.execute('''CREATE TABLE services (ComputerName TEXT, ipAddr text, AcceptPause text, AcceptStop text, Caption text, CheckPoint text, CreationClassName text, DelayedAutoStart text, Description text, DesktopInteract text, DisplayName text, ErrorControl text, ExitCode text, InstallDate text, Name text, PathName text, ProcessId text, ServiceSpecificExitCode text, ServiceType text, Started text, StartMode text, StartName text, State text, Status text, SystemCreationClassName text, SystemName text, TagId text, WaitHint text, unique (ComputerName, ipAddr, ProcessId, Caption))''')
			except sqlite3.OperationalError:
				pass
			for service in services:
				try:
					serviceData = (computerName, ipAddr, self.check(service, "AcceptPause"), self.check(service, "AcceptStop"), self.check(service, "Caption"), self.check(service, "CheckPoint"), self.check(service, "CreationClassName"), self.check(service, "DelayedAutoStart"), self.check(service, "Description"), self.check(service, "DesktopInteract"), self.check(service, "DisplayName"), self.check(service, "ErrorControl"), self.check(service, "ExitCode"), self.check(service, "InstallDate"), self.check(service, "Name"), self.check(service, "PathName"), self.check(service, "serviceId"), self.check(service, "ServiceSpecificExitCode"), self.check(service, "ServiceType"), self.check(service, "Started"), self.check(service, "StartMode"), self.check(service, "StartName"), self.check(service, "State"), self.check(service, "Status"), self.check(service, "SystemCreationClassName"), self.check(service, "SystemName"), self.check(service, "TagId"), self.check(service, "WaitHint"))
					c.execute('INSERT INTO services VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', serviceData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for service in services:
				print service
		return	
		
	def shares(self):
		remshares = self.w.Win32_Share()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				db.text_factory = str
				c = db.cursor()
				c.execute('''CREATE TABLE shares (ComputerName TEXT, ipAddr text, Caption text, Description text, InstallDate text, Status text, AccessMask text, AllowMaximum text, MaximumAllowed text, Name text, Path text, Type text, unique (ComputerName, ipAddr, Path))''')
			except sqlite3.OperationalError:
				pass
			for shares in remshares:
				try:
					shareData = (computerName, ipAddr, self.check(shares, "Caption"), self.check(shares, "Description"), self.check(shares, "InstallDate"), self.check(shares, "Status"), self.check(shares, "AccessMask"), self.check(shares, "AllowMaximum"), self.check(shares, "MaximumAllowed"), self.check(shares, "Name"), self.check(shares, "Path"), self.check(shares, "Type"))
					c.execute('INSERT INTO shares VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', shareData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for shares in remshares:
				print shares
		return

	def physicalDisks(self):
		drives = self.w.Win32_DiskDrive()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				db.text_factory = str
				c = db.cursor()
				c.execute('''CREATE TABLE physical_disks (ComputerName TEXT, ipAddr text, Availability text, BytesPerSector text, Capabilities text, CapabilityDescriptions text, Caption text, CompressionMethod text, ConfigManagerErrorCode text, ConfigManagerUserConfig text, CreationClassName text, DefaultBlockSize text, Description text, DeviceID text, ErrorCleared text, ErrorDescription text, ErrorMethodology text, FirmwareRevision text, _Index text, InstallDate text, InterfaceType text, LastErrorCode text, Manufacturer text, MaxBlockSize text, MaxMediaSize text, MediaLoaded text, MediaType text, MinBlockSize text, Model text, Name text, NeedsCleaning text, NumberOfMediaSupported text, Partitions text, PNPDeviceID text, PowerManagementCapabilities text, PowerManagementSupported text, SCSIBus text, SCSILogicalUnit text, SCSIPort text, SCSITargetId text, SectorsPerTrack text, SerialNumber text, Signature text, Size text, Status text, StatusInfo text, SystemCreationClassName text, SystemName text, TotalCylinders text, TotalHeads text, TotalSectors text, TotalTracks text, TracksPerCylinder text, unique (ComputerName, ipAddr, DeviceID))''')
			except sqlite3.OperationalError:
				pass
			for drive in drives:
				try:
					diskData = (computerName, ipAddr, self.check(drive, "Availability"), self.check(drive, "BytesPerSector"), self.check(drive, "Capabilities"), self.check(drive, "CapabilityDescriptions"), self.check(drive, "Caption"), self.check(drive, "CompressionMethod"), self.check(drive, "ConfigManagerErrorCode"), self.check(drive, "ConfigManagerUserConfig"), self.check(drive, "CreationClassName"), self.check(drive, "DefaultBlockSize"), self.check(drive, "Description"), self.check(drive, "DeviceID"), self.check(drive, "ErrorCleared"), self.check(drive, "ErrorDescription"), self.check(drive, "ErrorMethodology"), self.check(drive, "FirmwareRevision"), self.check(drive, "Index"), self.check(drive, "InstallDate"), self.check(drive, "InterfaceType"), self.check(drive, "LastErrorCode"), self.check(drive, "Manufacturer"), self.check(drive, "MaxBlockSize"), self.check(drive, "MaxMediaSize"), self.check(drive, "MediaLoaded"), self.check(drive, "MediaType"), self.check(drive, "MinBlockSize"), self.check(drive, "Model"), self.check(drive, "Name"), self.check(drive, "NeedsCleaning"), self.check(drive, "NumberOfMediaSupported"), self.check(drive, "Partitions"), self.check(drive, "PNPDeviceID"), self.check(drive, "PowerManagementCapabilities"), self.check(drive, "PowerManagementSupported"), self.check(drive, "SCSIBus"), self.check(drive, "SCSILogicalUnit"), self.check(drive, "SCSIPort"), self.check(drive, "SCSITargetId"), self.check(drive, "SectorsPerTrack"), self.check(drive, "SerialNumber"), self.check(drive, "Signature"), self.check(drive, "Size"), self.check(drive, "Status"), self.check(drive, "StatusInfo"), self.check(drive, "SystemCreationClassName"), self.check(drive, "SystemName"), self.check(drive, "TotalCylinders"), self.check(drive, "TotalHeads"), self.check(drive, "TotalSectors"), self.check(drive, "TotalTracks"), self.check(drive, "TracksPerCylinder"))
					c.execute('INSERT INTO physical_disks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', diskData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for drive in drives:
				print drive
		return
		
	def physicalMemory(self):
		memory = self.w.Win32_PhysicalMemory()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				db.text_factory = str
				c = db.cursor()
				c.execute('''CREATE TABLE physical_memory (ComputerName TEXT, ipAddr text, Attributes text, BankLabel text, Capacity text, Caption text, ConfiguredClockSpeed text, ConfiguredVoltage text, CreationClassName text, DataWidth text, Description text, DeviceLocator text, FormFactor text, HotSwappable text, InstallDate text, InterleaveDataDepth text, InterleavePosition text, Manufacturer text, MaxVoltage text, MemoryType text, MinVoltage text, Model text, Name text, OtherIdentifyingInfo text, PartNumber text, PositionInRow text, PoweredOn text, Removable text, Replaceable text, SerialNumber text, SKU text, SMBIOSMemoryType text, Speed text, Status text, Tag text, TotalWidth text, TypeDetail text, Version text, unique (ComputerName, ipAddr, SerialNumber, DeviceLocator))''')
			except sqlite3.OperationalError:
				pass
			for mem in memory:
				try:
					diskData = (computerName, ipAddr, self.check(mem, "Attributes"), self.check(mem, "BankLabel"), self.check(mem, "Capacity"), self.check(mem, "Caption"), self.check(mem, "ConfiguredClockSpeed"), self.check(mem, "ConfiguredVoltage"), self.check(mem, "CreationClassName"), self.check(mem, "DataWidth"), self.check(mem, "Description"), self.check(mem, "DeviceLocator"), self.check(mem, "FormFactor"), self.check(mem, "HotSwappable"), self.check(mem, "InstallDate"), self.check(mem, "InterleaveDataDepth"), self.check(mem, "InterleavePosition"), self.check(mem, "Manufacturer"), self.check(mem, "MaxVoltage"), self.check(mem, "MemoryType"), self.check(mem, "MinVoltage"), self.check(mem, "Model"), self.check(mem, "Name"), self.check(mem, "OtherIdentifyingInfo"), self.check(mem, "PartNumber"), self.check(mem, "PositionInRow"), self.check(mem, "PoweredOn"), self.check(mem, "Removable"), self.check(mem, "Replaceable"), self.check(mem, "SerialNumber"), self.check(mem, "SKU"), self.check(mem, "SMBIOSMemoryType"), self.check(mem, "Speed"), self.check(mem, "Status"), self.check(mem, "Tag"), self.check(mem, "TotalWidth"), self.check(mem, "TypeDetail"), self.check(mem, "Version"))
					c.execute('INSERT INTO physical_memory VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', diskData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for mem in memory:
				print mem
		return
		
	def patches(self):
		fixes = self.w.Win32_QuickFixEngineering()
		if self.database != "":
			try:
				db = sqlite3.connect(self.database)
				db.text_factory = str
				c = db.cursor()
				c.execute('''CREATE TABLE physical_memory (ComputerName TEXT, ipAddr text, Caption TEXT, Description TEXT, InstallDate TEXT, Name TEXT, Status TEXT, CSName TEXT, FixComments TEXT, HotFixID TEXT, InstalledBy TEXT, InstalledOn TEXT, ServicePackInEffect TEXT, unique (ComputerName, ipAddr, Caption))''')
			except sqlite3.OperationalError:
				pass
			for fix in fixes:
				try:
					diskData = (computerName, ipAddr, self.check(fix, "Caption"), self.check(fix, "Description"), self.check(fix, "InstallDate"), self.check(fix, "Name"), self.check(fix, "Status"), self.check(fix, "CSName"), self.check(fix, "FixComments"), self.check(fix, "HotFixID"), self.check(fix, "InstalledBy"), self.check(fix, "InstalledOn"), self.check(fix, "ServicePackInEffect"))
					c.execute('INSERT INTO physical_memory VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', diskData)
				except sqlite3.IntegrityError:
					pass
			db.commit()
			db.close()
		if self.stout:
			for fix in fixes:
				print fix
		return