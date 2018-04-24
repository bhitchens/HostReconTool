import wmi, sqlite3, sys, math, netaddr, socket

class WMIConnection:
	
	ipAddr = ""
	database = ""
	computerName = ""
	stout = False
	
	def __init__(self, remote, user, password, verbose):
		self.remote = remote
		self.user = user
		self.password = password
		self.w = None
		self.verbose = verbose
		global ipAddr
		#if a remote IP has been provided, set the ipAddr global to that IP
		if remote != "":
			ipAddr = str(remote)
		#else set it to the local system's IP
		else:
			ipAddr = socket.gethostbyname(socket.gethostname())
		
	#make a WMI connection with a non-standard namespace
	def connect(self, cursor, namespace):
		if self.password != "":
			self.w = wmi.WMI(self.remote, user=self.user, password=self.password, namespace=mNamespace)
		elif self.user != "":
			self.w = wmi.WMI(self.remote, user=self.user, namespace=mNamespace)
		elif self.remote != "":
			self.w = wmi.WMI(self.remote, namespace=mNamespace)
		else:
			self.w = wmi.WMI(namespace=mNamespace)
		self.c = cursor

	#make a WMI connection with the standard namespace
	def connect(self, cursor):
		if self.password != "":
			self.w = wmi.WMI(self.remote, user=self.user, password=self.password)
		elif self.user != "":
			self.w = wmi.WMI(self.remote, user=self.user)
		elif self.remote != "":
			self.w = wmi.WMI(self.remote)
		else:
			self.w = wmi.WMI()
		self.c = cursor
	
	#use eval to access each attribute under a try/except paradigm	
	def check(self, obj, attrib):
		try:
			return (eval("obj." + attrib)).encode('utf-8')
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
		self.patches()
		self.bios()
		self.pnp()
		
	#enter data from wmi query into db
	def dbEntry(self, itemList, uniqueList, name, dataList):
		try:
			#create table
			self.c.execute('''CREATE TABLE ''' + name + ''' (ComputerName TEXT, ipAddr text,''' + (''' {} text,''' * len(itemList)).format(*itemList) +  '''unique (''' + uniqueList + '''))''')
		except sqlite3.OperationalError:
			pass
		try:
			#for each object in the data list
			for data in dataList:
				#initial values for all table entries
				values = [computerName, ipAddr]
				#for each potential element of the object, add it to the values list
				for item in itemList:
					values.append(self.check(data, item.replace("__","")))
				#enter the values into the db
				self.c.execute('INSERT INTO ' + name + ' VALUES (?' + ', ?' * (len(values) - 1) + ')', values)
		except sqlite3.IntegrityError:
			pass

	#comments on this method apply to the other WMI methods
	def sysData(self):
		if (self.verbose): print "Fetching System Data"
		#get the WMI data
		sys = [self.w.Win32_ComputerSystem()[0]]
		
		#get the computer name
		global computerName
		computerName = sys[0].Name
		
		#if a db has been provided
		if self.database != "":
			#list of every element of the wmi object
			itemList = ("AdminPasswordStatus", "AutomaticManagedPagefile", "AutomaticResetBootOption", "AutomaticResetCapability", "BootROMSupported", "BootStatus", "BootupState", "Caption", "ChassisBootupState", "ChassisSKUNumber", "CreationClassName", "CurrentTimeZone", "Description", "DNSHostName", "Domain", "DomainRole", "EnableDaylightSavingsTime", "FrontPanelResetStatus", "HypervisorPresent", "InfraredSupported", "KeyboardPasswordStatus", "Manufacturer", "Model", "NetworkServerModeEnabled", "NumberOfLogicalProcessors", "NumberOfProcessors", "OEMArray", "PartOfDomain", "PauseAfterReset", "PCSystemType", "PCSystemTypeEx", "PowerOnPasswordStatus", "PowerState", "PowerSupplyState", "PrimaryOwnerName", "ResetCapability", "ResetCount", "ResetLimit", "Roles", "Status", "SystemFamily", "SystemSKUNumber", "SystemType", "ThermalState", "TotalPhysicalMemory", "UserName", "WakeUpType", "Workgroup")
			
			#unique values for the db
			uniqueList = "ComputerName, ipAddr"
			
			#call the db entry function
			self.dbEntry(itemList, uniqueList, "sys_data", sys)			
						
		#if standard out is selected, print the WMI data to standard out
		if self.stout:
			print sys
		return
	
	def userData(self):
		if (self.verbose): print "Fetching user data"
		accounts = self.w.Win32_UserAccount()
		if self.database != "":
			itemList = ("AccountType", "Caption", "Description", "Disabled", "Domain", "FullName", "LocalAccount", "Lockout", "Name", "PasswordChangeable", "PasswordExpires", "PasswordRequired", "SID", "SIDType", "Status")
			uniqueList = "ComputerName, ipAddr, SID"
			self.dbEntry(itemList, uniqueList, "user_data", accounts)
		if self.stout:
			for account in accounts:
				print account
		return

	def netLogin(self):
		if (self.verbose): print "Fetching net login data"
		logins = self.w.Win32_NetworkLoginProfile()
		if self.database != "":
			itemList = ("Caption", "Description", "SettingID", "AccountExpires", "AuthorizationFlags", "BadPasswordCount", "CodePage", "Comment", "CountryCode", "Flags", "FullName", "HomeDirectory", "HomeDirectoryDrive", "LastLogoff", "LastLogon", "LogonHours", "LogonServer", "MaximumStorage", "Name", "NumberOfLogons", "Parameters", "PasswordAge", "PasswordExpires", "PrimaryGroupId", "Privileges", "Profile", "ScriptPath", "UnitsPerWeek", "UserComment", "UserId", "UserType", "Workstations")
			uniqueList = "ComputerName, ipAddr, Caption"
			self.dbEntry(itemList, uniqueList, "net_login", logins)	
		if self.stout:
			for login in logins:
				print login
		return
				
	def groupData(self):
		if (self.verbose): print "Fetching group data"
		groups = self.w.Win32_Group()
		if self.database != "":
			itemList = ("Caption","Description","Domain","LocalAccount","Name","SID","SIDType","Status")
			uniqueList = "ComputerName, ipAddr, SID"
			name = "group_data"
			self.dbEntry(itemList, uniqueList, name, groups)
		if self.stout:
			for group in groups:
				print group
		return	

	def logicalDisks(self):		
		if (self.verbose): print "Fetching logical disk data"
		disks = self.w.Win32_LogicalDisk()
		if self.database != "":
			itemList = ("Access", "Availability", "BlockSize", "Caption", "Compressed", "ConfigManagerErrorCode", "ConfigManagerUserConfig", "CreationClassName", "Description", "DeviceID", "DriveType", "ErrorCleared", "ErrorDescription", "ErrorMethodology", "FileSystem", "FreeSpace", "InstallDate", "LastErrorCode", "MaximumComponentLength", "MediaType", "Name", "NumberOfBlocks", "PNPDeviceID", "PowerManagementSupported", "ProviderName", "Purpose", "QuotasDisabled", "QuotasIncomplete", "QuotasRebuilding", "Size", "Status", "StatusInfo", "SupportsDiskQuotas", "SupportsFileBasedCompression", "SystemCreationClassName", "SystemName", "VolumeDirty", "VolumeName", "VolumeSerialNumber")
			uniqueList = "ComputerName, ipAddr, Caption"
			self.dbEntry(itemList, uniqueList, "logical_disks", disks)	
		if self.stout:
			for disk in disks:
				print disk
		return
		
	def timeZone(self):
		if (self.verbose): print "Fetching time zone data"
		zones = self.w.Win32_TimeZone()
		if self.database != "":
			itemList = ("Caption", "Description", "SettingID", "Bias", "DaylightBias", "DaylightDay", "DaylightDayOfWeek", "DaylightHour", "DaylightMillisecond", "DaylightMinute", "DaylightMonth", "DaylightName", "DaylightSecond", "DaylightYear", "StandardBias", "StandardDay", "StandardDayOfWeek", "StandardHour", "StandardMillisecond", "StandardMinute", "StandardMonth", "StandardName", "StandardSecond", "StandardYear")
			uniqueList = "ComputerName, ipAddr"
			self.dbEntry(itemList, uniqueList, "time_zone", zones)
		if self.stout:
			for zone in zones:
				print zone
		return
		
	def startupPrograms(self):
		if (self.verbose): print "Fetching startup programs"
		programs = self.w.Win32_StartupCommand()
		if self.database != "":
			itemList = ("Caption", "Description", "SettingID", "Command", "Location", "Name", "User", "UserSID")
			uniqueList = "ComputerName, ipAddr, Caption, UserSID"
			self.dbEntry(itemList, uniqueList, "startup_programs", programs)
		if self.stout:
			for program in programs:
				print program
		return

	def userProfiles(self):
		if (self.verbose): print "Fetching user profiles"
		profiles = self.w.Win32_UserProfile()
		if self.database != "":
			itemList = ("SID", "LocalPath", "Loaded", "refCount", "Special", "RoamingConfigured", "RoamingPath", "RoamingPreference", "Status", "LastUseTime", "LastDownloadTime", "LastUploadTime", "HealthStatus", "LastAttemptedProfileDownloadTime", "LastAttemptedProfileUploadTime", "LastBackgroundRegistryUploadTime", "AppDataRoaming", "Desktop", "StartMenu", "Documents", "Pictures", "Music", "Videos", "Favorites", "Contacts", "Downloads", "Links", "Searches", "SavedGames")
			uniqueList = "ComputerName, ipAddr, SID, LastUseTime"
			self.dbEntry(itemList, uniqueList, "user_profiles", profiles)
		if self.stout:
			for profile in profiles:
				print profile
		return		
		
	def networkAdapters(self):
		if (self.verbose): print "Fetching network adapter data"
		adapters = self.w.Win32_NetworkAdapterConfiguration()
		if self.database != "":
			itemList = ("Caption", "Description", "SettingID", "ArpAlwaysSourceRoute", "ArpUseEtherSNAP", "DatabasePath", "DeadGWDetectEnabled", "DefaultIPGateway", "DefaultTOS", "DefaultTTL", "DHCPEnabled", "DHCPLeaseExpires", "DHCPLeaseObtained", "DHCPServer", "DNSDomain", "DNSDomainSuffixSearchOrder", "DNSEnabledForWINSResolution", "DNSHostName", "DNSServerSearchOrder", "DomainDNSRegistrationEnabled", "ForwardBufferMemory", "FullDNSRegistrationEnabled", "GatewayCostMetric", "IGMPLevel", "Index__", "InterfaceIndex", "IPAddress", "IPConnectionMetric", "IPEnabled", "IPFilterSecurityEnabled", "IPPortSecurityEnabled", "IPSecPermitIPProtocols", "IPSecPermitTCPPorts", "IPSecPermitUDPPorts", "IPSubnet", "IPUseZeroBroadcast", "IPXAddress", "IPXEnabled", "IPXFrameType", "IPXMediaType", "IPXNetworkNumber", "IPXVirtualNetNumber", "KeepAliveInterval", "KeepAliveTime", "MACAddress", "MTU", "NumForwardPackets", "PMTUBHDetectEnabled", "PMTUDiscoveryEnabled", "ServiceName", "TcpipNetbiosOptions", "TcpMaxConnectRetransmissions", "TcpMaxDataRetransmissions", "TcpNumConnections", "TcpUseRFC1122UrgentPointer", "TcpWindowSize", "WINSEnableLMHostsLookup", "WINSHostLookupFile", "WINSPrimaryServer", "WINSScopeID", "WINSSecondaryServer")
			uniqueList = "ComputerName, ipAddr, MACAddress"
			self.dbEntry(itemList, uniqueList, "network_adapters", adapters)
		if self.stout:
			for adapter in adapters:
				print adapter
		return

	def processes(self):
		if (self.verbose): print "Fetching processes"
		processes = self.w.win32_process()
		if self.database != "":
			itemList = ("CreationClassName", "Caption", "CommandLine", "CreationDate", "CSCreationClassName", "CSName", "Description", "ExecutablePath", "ExecutionState", "Handle", "HandleCount", "InstallDate", "KernelModeTime", "MaximumWorkingSetSize", "MinimumWorkingSetSize", "Name", "OSCreationClassName", "OSName", "OtherOperationCount", "OtherTransferCount", "PageFaults", "PageFileUsage", "ParentProcessId", "PeakPageFileUsage", "PeakVirtualSize", "PeakWorkingSetSize", "Priority", "PrivatePageCount", "ProcessId", "QuotaNonPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaPeakPagedPoolUsage", "ReadOperationCount", "ReadTransferCount", "SessionId", "Status", "TerminationDate", "ThreadCount", "UserModeTime", "VirtualSize", "WindowsVersion", "WorkingSetSize", "WriteOperationCount", "WriteTransferCount")
			uniqueList = "ComputerName, ipAddr, ProcessId"
			self.dbEntry(itemList, uniqueList, "processes", processes)
		if self.stout:
			for process in processes:
				print process
		return
		
	def services(self):
		if (self.verbose): print "Fetching services"
		services = self.w.win32_Service()
		if self.database != "":
			itemList = ("AcceptPause", "AcceptStop", "Caption", "CheckPoint", "CreationClassName", "DelayedAutoStart", "Description", "DesktopInteract", "DisplayName", "ErrorControl", "ExitCode", "InstallDate", "Name", "PathName", "serviceId", "ServiceSpecificExitCode", "ServiceType", "Started", "StartMode", "StartName", "State", "Status", "SystemCreationClassName", "SystemName", "TagId", "WaitHint")
			uniqueList = "ComputerName, ipAddr, serviceId, Caption"
			self.dbEntry(itemList, uniqueList, "services", services)
		if self.stout:
			for service in services:
				print service
		return	
		
	def shares(self):
		if (self.verbose): print "Fetching shares"
		remshares = self.w.Win32_Share()
		if self.database != "":
			itemList = ("Caption", "Description", "InstallDate", "Status", "AccessMask", "AllowMaximum", "MaximumAllowed", "Name", "Path", "Type")
			uniqueList = "ComputerName, ipAddr, Path"
			self.dbEntry(itemList, uniqueList, "shares", remshares)
		if self.stout:
			for shares in remshares:
				print shares
		return

	def physicalDisks(self):
		if (self.verbose): print "Fetching physical disk data"
		drives = self.w.Win32_DiskDrive()
		if self.database != "":
			itemList = ("Availability", "BytesPerSector", "Capabilities", "CapabilityDescriptions", "Caption", "CompressionMethod", "ConfigManagerErrorCode", "ConfigManagerUserConfig", "CreationClassName", "DefaultBlockSize", "Description", "DeviceID", "ErrorCleared", "ErrorDescription", "ErrorMethodology", "FirmwareRevision", "Index__", "InstallDate", "InterfaceType", "LastErrorCode", "Manufacturer", "MaxBlockSize", "MaxMediaSize", "MediaLoaded", "MediaType", "MinBlockSize", "Model", "Name", "NeedsCleaning", "NumberOfMediaSupported", "Partitions", "PNPDeviceID", "PowerManagementCapabilities", "PowerManagementSupported", "SCSIBus", "SCSILogicalUnit", "SCSIPort", "SCSITargetId", "SectorsPerTrack", "SerialNumber", "Signature", "Size", "Status", "StatusInfo", "SystemCreationClassName", "SystemName", "TotalCylinders", "TotalHeads", "TotalSectors", "TotalTracks", "TracksPerCylinder")
			uniqueList = "ComputerName, ipAddr, DeviceID"
			self.dbEntry(itemList, uniqueList, "physical_disks", drives)
		if self.stout:
			for drive in drives:
				print drive
		return
		
	def physicalMemory(self):
		if (self.verbose): print "Fetching physical memory data"
		memory = self.w.Win32_PhysicalMemory()
		if self.database != "":
			itemList = ("Attributes", "BankLabel", "Capacity", "Caption", "ConfiguredClockSpeed", "ConfiguredVoltage", "CreationClassName", "DataWidth", "Description", "DeviceLocator", "FormFactor", "HotSwappable", "InstallDate", "InterleaveDataDepth", "InterleavePosition", "Manufacturer", "MaxVoltage", "MemoryType", "MinVoltage", "Model", "Name", "OtherIdentifyingInfo", "PartNumber", "PositionInRow", "PoweredOn", "Removable", "Replaceable", "SerialNumber", "SKU", "SMBIOSMemoryType", "Speed", "Status", "Tag", "TotalWidth", "TypeDetail", "Version")
			uniqueList = "ComputerName, ipAddr, SerialNumber, DeviceLocator"
			self.dbEntry(itemList, uniqueList, "physical_memory", memory)
		if self.stout:
			for mem in memory:
				print mem
		return
		
	def patches(self):
		if (self.verbose): print "Fetching patch data"
		fixes = self.w.Win32_QuickFixEngineering()
		if self.database != "":
			itemList = ("Caption", "Description", "InstallDate", "Name", "Status", "CSName", "FixComments", "HotFixID", "InstalledBy", "InstalledOn", "ServicePackInEffect")
			uniqueList = "ComputerName, ipAddr, Caption"
			self.dbEntry(itemList, uniqueList, "patch_data", fixes)
		if self.stout:
			for fix in fixes:
				print fix
		return		
		
	def bios(self):
		if (self.verbose): print "Fetching BIOS data"
		bios = self.w.Win32_BIOS()
		if self.database != "":
			itemList = ("BiosCharacteristics", "BIOSVersion", "BuildNumber", "Caption", "CodeSet", "CurrentLanguage", "Description", "EmbeddedControllerMajorVersion", "EmbeddedControllerMinorVersion", "IdentificationCode", "InstallableLanguages", "InstallDate", "LanguageEdition", "ListOfLanguages", "Manufacturer", "Name", "OtherTargetOS", "PrimaryBIOS", "ReleaseDate", "SerialNumber", "SMBIOSBIOSVersion", "SMBIOSMajorVersion", "SMBIOSMinorVersion", "SMBIOSPresent", "SoftwareElementID", "SoftwareElementState", "Status", "SystemBiosMajorVersion", "SystemBiosMinorVersion", "TargetOperatingSystem", "Version")
			uniqueList = "ComputerName, ipAddr, BIOSVersion"
			self.dbEntry(itemList, uniqueList, "bios_data", bios)
		if self.stout:
			for b in bios:
				print b
		return
		
	def pnp(self):
		if (self.verbose): print "Fetching PlugNPlay data"
		pnp = self.w.Win32_PNPEntity()
		if self.database != "":
			itemList = ("Availability", "Caption", "ClassGuid", "CompatibleID", "ConfigManagerErrorCode", "ConfigManagerUserConfig", "CreationClassName", "Description", "DeviceID", "ErrorCleared", "ErrorDescription", "HardwareID", "InstallDate", "LastErrorCode", "Manufacturer", "Name", "PNPClass", "PNPDeviceID", "PowerManagementCapabilities", "PowerManagementSupported", "Present", "Service", "Status", "StatusInfo", "SystemCreationClassName", "SystemName")
			uniqueList = "ComputerName, ipAddr, ClassGuid"
			self.dbEntry(itemList, uniqueList, "plugnplay", pnp)
		if self.stout:
			for plug in pnp:
				print plug
		return
		
	def drivers(self):
		if (self.verbose): print "Fetching driver data"
		try:
			drivers = self.w.Win32_SystemDriver()
			if self.database != "":
				itemList = ("AcceptPause", "AcceptStop", "Caption", "CreationClassName", "Description", "DesktopInteract", "DisplayName", "ErrorControl", "ExitCode", "InstallDate", "Name", "PathName", "ServiceSpecificExitCode", "ServiceType", "Started", "StartMode", "StartName", "State", "Status", "SystemCreationClassName", "SystemName", "TagId")
				uniqueList = "ComputerName, ipAddr, PathName"
				self.dbEntry(itemList, uniqueList, "system_drivers", drivers)
			if self.stout:
				for driver in drivers:
					print driver
			return
		except AttributeError:
			if (self.verbose): print "Failed to fetch driver data"
			return			