#Checks for output folder preference text file. If one does not exist, use the curent folder.
$DestinationTXT = Test-Path .\dest.txt
    If ($DestinationTXT -eq $false) {
        $DestinationFolder = ".\Computers"
    }
    else {
        $DestinationFolder = Get-Content .\dest.txt
    }
function Get-Inventory {
    [CmdletBinding()]
    param (
    [PSDefaultValue(Help = 'Current directory')]
    $DestinationFolder = '.\Computers'
    )

$DestinationFolderPath = Test-Path $DestinationFolder
    If ($DestinationFolderPath -eq 'True') {
        Write-Verbose "Using existing folder: $($DestinationFolder)" -Verbose
    } 
    Else {
        mkdir "$($DestinationFolder)"
    }


$ComputerName = hostname
$user = $env:username
$DesktopPath = [Environment]::GetFolderPath("Desktop")

#Date
    $Date =  Get-Date -Format "yyyy-MM-dd HH:mm:ss"

#CIM
    $System = Get-CimInstance Win32_ComputerSystem
    $BIOS = Get-CimInstance Win32_BIOS
    $SoftwareLicensing = Get-WmiObject SoftwareLicensingService
    $Win32Processor = Get-CimInstance Win32_Processor
    $Win32DiskDrive = Get-CimInstance Win32_DiskDrive
    $Win32MSFTPhysicalDisk = Get-CimInstance MSFT_PhysicalDisk -Namespace Root\Microsoft\Windows\Storage
    $WinOperatingSystem = Get-CimInstance Win32_OperatingSystem
    $Win32PhysicalMemory = Get-CimInstance Win32_PhysicalMemory
    $VideoController = Get-CimInstance win32_VideoController

#IP octets
    $ipID = ipconfig | Where-Object {$_ -match "IPv4 Address"} | ForEach-Object{$_.Split(":")[1]}
    $oct0 = $ipID.trim().Split(".")[0]
    $oct1 = $ipID.trim().Split(".")[1]
    $oct2 = $ipID.trim().Split(".")[2]
    $oct3 = $ipID.trim().Split(".")[3]




Get-Disk | Select-Object DiskNumber, PartitionStyle, ProvisioningType, OperationalStatus, HealthStatus, BusType, UniqueIdFormat, OfflineReason, ObjectId, PassThroughClass, PassThroughIds, PassThroughNamespace, PassThroughServer, UniqueId, AdapterSerialNumber, AllocatedSize, BootFromDisk, FirmwareVersion, FriendlyName, Guid, IsBoot, IsClustered, IsHighlyAvailable, IsOffline, IsReadOnly, IsScaleOut, IsSystem, LargestFreeExtent, Location, LogicalSectorSize, Manufacturer, Model, Number, NumberOfPartitions, Path, PhysicalSectorSize, SerialNumber, Signature, Size, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompDisk.csv -Append -NoTypeInformation

Get-Volume |Select-Object OperationalStatus, HealthStatus, DriveType, FileSystemType, DedupMode, ObjectId, PassThroughClass, PassThroughIds, PassThroughNamespace, PassThroughServer, UniqueId, AllocationUnitSize, DriveLetter, FileSystem, FileSystemLabel, Path, Size, SizeRemaining, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompVolume.csv -Append -NoTypeInformation

$Win32DiskDrive | Select-Object PSComputerName, ConfigManagerErrorCode, LastErrorCode, NeedsCleaning, Status, DeviceID, StatusInfo, Partitions, BytesPerSector, ConfigManagerUserConfig, DefaultBlockSize, Index, InstallDate, InterfaceType, MaxBlockSize, MaxMediaSize, MinBlockSize, NumberOfMediaSupported, SectorsPerTrack, Size, TotalCylinders, TotalHeads, TotalSectors, TotalTracks, TracksPerCylinder, __GENUS, __CLASS, __SUPERCLASS, __DYNASTY, __RELPATH, __PROPERTY_COUNT, __DERIVATION, __SERVER, __NAMESPACE, __PATH, Availability, Capabilities, CapabilityDescriptions, Caption, CompressionMethod, CreationClassName, Description, ErrorCleared, ErrorDescription, ErrorMethodology, FirmwareRevision, Manufacturer, MediaLoaded, MediaType, Model, Name, PNPDeviceID, PowerManagementCapabilities, PowerManagementSupported, SCSIBus, SCSILogicalUnit, SCSIPort, SCSITargetId, SerialNumber, Signature, SystemCreationClassName, SystemName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompDrive.csv -Append -NoTypeInformation

$Win32MSFTPhysicalDisk |Select-Object ClassName, Usage, OperationalStatus, UniqueIdFormat, HealthStatus, BusType, CannotPoolReason, SupportedUsages, MediaType, SpindleSpeed, ObjectId, PassThroughClass, PassThroughIds, PassThroughNamespace, PassThroughServer, UniqueId, Description, FriendlyName, Manufacturer, Model, OperationalDetails, PhysicalLocation, SerialNumber, AdapterSerialNumber, AllocatedSize, CanPool, DeviceId, EnclosureNumber, FirmwareVersion, IsIndicationEnabled, IsPartial, LogicalSectorSize, OtherCannotPoolReasonDescription, PartNumber, PhysicalSectorSize, Size, SlotNumber, SoftwareVersion, StoragePoolUniqueId, VirtualDiskFootprint, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\PhysicalDisk.csv -Append -NoTypeInformation




#System
Write-Output "Windows: $($SoftwareLicensing.Version)"
$ProductKey = $SoftwareLicensing.OA3xOriginalProductKey 
Write-Verbose "Key: $ProductKey" -Verbose


Write-Output "CPU: $( $Win32Processor.Name)"
$MaxGHz =  $Win32Processor | ForEach-Object {[math]::Round($_.MaxClockSpeed / 10)}    #Rounds the clock speed to go from MHz to GHz.
$MaxGHz = "$($MaxGHz / 100) GHz"    #Adds the decimal place and GHz label.

#Memory
$memory = Get-WmiObject Win32_computersystem | ForEach-Object {[math]::round($_.totalPhysicalMemory / 1GB)}   #Displays the amount of system memory rounded to the nearest gigabyte.
Write-Output "RAM: $($memory) GB"

$FreeMemory = [math]::Round($WinOperatingSystem.FreePhysicalMemory/1mb,2)
$FreeMemoryPercent = [math]::Round(($WinOperatingSystem.FreePhysicalMemory/$WinOperatingSystem.TotalVisibleMemorySize)*100,2)



$WinOperatingSystem | Select-Object Status, Name, FreePhysicalMemory, FreeSpaceInPagingFiles, FreeVirtualMemory, Caption, Description, InstallDate, CreationClassName, CSCreationClassName, CSName, CurrentTimeZone, Distributed, LastBootUpTime, LocalDateTime, MaxNumberOfProcesses, MaxProcessMemorySize, NumberOfLicensedUsers, NumberOfProcesses, NumberOfUsers, OSType, OtherTypeDescription, SizeStoredInPagingFiles, TotalSwapSpaceSize, TotalVirtualMemorySize, TotalVisibleMemorySize, Version, BootDevice, BuildNumber, BuildType, CodeSet, CountryCode, CSDVersion, DataExecutionPrevention_32BitApplications, DataExecutionPrevention_Available, DataExecutionPrevention_Drivers, DataExecutionPrevention_SupportPolicy, Debug, EncryptionLevel, ForegroundApplicationBoost, LargeSystemCache, Locale, Manufacturer, MUILanguages, OperatingSystemSKU, Organization, OSArchitecture, OSLanguage, OSProductSuite, PAEEnabled, PlusProductID, PlusVersionNumber, PortableOperatingSystem, Primary, ProductType, RegisteredUser, SerialNumber, ServicePackMajorVersion, ServicePackMinorVersion, SuiteMask, SystemDevice, SystemDirectory, SystemDrive, WindowsDirectory, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompOS.csv -Append -NoTypeInformation

$Win32PhysicalMemory | Select-Object Caption, Description, InstallDate, Name, Status, CreationClassName, Manufacturer, Model, OtherIdentifyingInfo, PartNumber, PoweredOn, SerialNumber, SKU, Tag, Version, HotSwappable, Removable, Replaceable, FormFactor, BankLabel, Capacity, DataWidth, InterleavePosition, MemoryType, PositionInRow, Speed, TotalWidth, Attributes, ConfiguredClockSpeed, ConfiguredVoltage, DeviceLocator, InterleaveDataDepth, MaxVoltage, MinVoltage, SMBIOSMemoryType, TypeDetail, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompMemory.csv -Append -NoTypeInformation


<#CPU#>
    $CompCPU = [PSCustomObject]@{
        'ExtClock'                                = $Win32Processor.ExtClock;
        'L2CacheSize'                             = $Win32Processor.L2CacheSize
        'L2CacheSpeed'                            = $Win32Processor.L2CacheSpeed
        'MaxClockSpeed'                           = $Win32Processor.MaxClockSpeed;
        'PowerManagementSupported'                = $Win32Processor.PowerManagementSupported;
        'ProcessorType'                           = $Win32Processor.ProcessorType;
        'Revision'                                = $Win32Processor.Revision;
        'SocketDesignation'                       = $Win32Processor.SocketDesignation;
        'VoltageCaps'                             = $Win32Processor.VoltageCaps;
        'Architecture'                            = $Win32Processor.Architecture;
        'Caption'                                 = $Win32Processor.Caption;
        'CurrentVoltage'                          = $Win32Processor.CurrentVoltage;   
        'CurrentClockSpeed'                       = $Win32Processor.CurrentClockSpeed;
        'Description'                             = $Win32Processor.Description;
        'Family'                                  = $Win32Processor.Family;
        'L3CacheSize'                             = $Win32Processor.L3CacheSize;
        'L3CacheSpeed'                            = $Win32Processor.L3CacheSpeed;
        'Level'                                   = $Win32Processor.Level;
        'Manufacturer'                            = $Win32Processor.Manufacturer;
        'Name'                                    = $Win32Processor.Name;
        'NumberOfCores'                           = $Win32Processor.NumberOfCores;
        'NumberOfLogicalProcessors'               = $Win32Processor.NumberOfLogicalProcessors;
        'OtherFamilyDescription'                  = $Win32Processor.OtherFamilyDescription;
        'PartNumber'                              = $Win32Processor.PartNumber;
        'PNPDeviceID'                             = $Win32Processor.PNPDeviceID;
        'PowerManagementCapabilities'             = $Win32Processor.PowerManagementCapabilities;
        'ProcessorId'                             = $Win32Processor.ProcessorId;
        'SecondLevelAddressTranslationExtensions' = $Win32Processor.SecondLevelAddressTranslationExtensions;
        'SerialNumber'                            = $Win32Processor.SerialNumber;
        'Stepping'                                = $Win32Processor.Stepping;
        'SystemName'                              = $Win32Processor.SystemName;
        'ThreadCount'                             = $Win32Processor.ThreadCount;
        'UniqueId'                                = $Win32Processor.UniqueId;
        'UpgradeMethod'                           = $Win32Processor.UpgradeMethod;
        'ComputerSerialNumber'                    = $bios.SerialNumber;
        'Timestamp'                               = $date;
    }

<#     $TestCPUCSV = Test-Path ".\Computers\CompCPU.csv"
    If ($TestCPUCSV -eq $true) {
        Write-Verbose "Using existing folder: .\Computers\CompCPU.csv" -Verbose
    } 
    Else {
        New-Item -ItemType File -Path .\Computers -Name CompCPU.csv
    }

    $GetCompCPU = Get-Content .\Computers\CompCPU.csv | Select-String -Pattern ($Win32Processor.Name)
    if ($null -eq $GetCompCPU) { #>
        $CompCPU | Export-Csv -Path $DestinationFolder\CPU.csv -Append -NoTypeInformation
<#     }
    else {
        Write-Verbose "CPU already in database. Skipping..."
    } #>

<#GPU#>  
    $CompGPU = [PSCustomObject]@{
        'InstallDate'                 = $VideoController.InstallDate;
        'Name'                        = $VideoController.Name;
        'Status'                      = $VideoController.Status;
        'Availability'                = $VideoController.Availability;
        'ConfigManagerErrorCode'      = $VideoController.ConfigManagerErrorCode;
        'ConfigManagerUserConfig'     = $VideoController.ConfigManagerUserConfig;
        'DeviceID'                    = $VideoController.DeviceID;
        'CurrentHorizontalResolution' = $VideoController.CurrentHorizontalResolution;
        'CurrentNumberOfColors'       = $VideoController.CurrentNumberOfColors;
        'CurrentNumberOfColumns'      = $VideoController.CurrentNumberOfColumns;
        'CurrentNumberOfRows'         = $VideoController.CurrentNumberOfRows;
        'CurrentRefreshRate'          = $VideoController.CurrentRefreshRate;
        'CurrentScanMode'             = $VideoController.CurrentScanMode;
        'CurrentVerticalResolution'   = $VideoController.CurrentVerticalResolution;
        'MaxRefreshRate'              = $VideoController.MaxRefreshRate;
        'MinRefreshRate'              = $VideoController.MinRefreshRate;
        'VideoMemoryType'             = $VideoController.VideoMemoryType;
        'VideoProcessor'              = $VideoController.VideoProcessor;
        'VideoArchitecture'           = $VideoController.VideoArchitecture;
        'AdapterCompatibility'        = $VideoController.AdapterCompatibility -replace ",", "";
        'AdapterDACType'              = $VideoController.AdapterDACType;
        'AdapterRAM'                  = $VideoController.AdapterRAM;
        'DitherType'                  = $VideoController.DitherType;
        'DriverDate'                  = $VideoController.DriverDate;
        'DriverVersion'               = $VideoController.DriverVersion;
        'InfFilename'                 = $VideoController.InfFilename;
        'InfSection'                  = $VideoController.InfSection;
        'VideoModeDescription'        = $VideoController.VideoModeDescription
        'UpgradeMethod'               = $Win32Processor.UpgradeMethod;
        'ComputerSerialNumber'        = $bios.SerialNumber;
        'Timestamp'                   = $date;
    }
    $CompGPU | Export-Csv -Path $DestinationFolder\GPU.csv -Append -NoTypeInformation

Get-NetAdapter |Select-Object MacAddress, Status, LinkSpeed, MediaType, PhysicalMediaType, AdminStatus, MediaConnectionState, DriverInformation, DriverFileName, NdisVersion, ifOperStatus, ifAlias, InterfaceAlias, ifIndex, ifDesc, ifName, DriverVersion, LinkLayerAddress, Caption, Description, ElementName, InstanceID, CommunicationStatus, DetailedStatus, HealthState, InstallDate, Name, OperatingStatus, OperationalStatus, PrimaryStatus, StatusDescriptions, AvailableRequestedStates, EnabledDefault, EnabledState, OtherEnabledState, RequestedState, TimeOfLastStateChange, TransitioningToState, AdditionalAvailability, Availability, CreationClassName, DeviceID, ErrorCleared, ErrorDescription, IdentifyingDescriptions, LastErrorCode, MaxQuiesceTime, OtherIdentifyingInfo, PowerManagementCapabilities, PowerManagementSupported, PowerOnHours, StatusInfo, SystemCreationClassName, SystemName, TotalPowerOnHours, MaxSpeed, OtherPortType, PortType, RequestedSpeed, Speed, UsageRestriction, ActiveMaximumTransmissionUnit, AutoSense, FullDuplex, LinkTechnology, NetworkAddresses, OtherLinkTechnology, OtherNetworkPortType, PermanentAddress, PortNumber, SupportedMaximumTransmissionUnit, AdminLocked, ComponentID, ConnectorPresent, DeviceName, DeviceWakeUpEnable, DriverDate, DriverDateData, DriverDescription, DriverMajorNdisVersion, DriverMinorNdisVersion, DriverName, DriverProvider, DriverVersionString, EndPointInterface, HardwareInterface, Hidden, HigherLayerInterfaceIndices, IMFilter, InterfaceAdminStatus, InterfaceDescription, InterfaceGuid, InterfaceIndex, InterfaceName, InterfaceOperationalStatus, InterfaceType, iSCSIInterface, LowerLayerInterfaceIndices, MajorDriverVersion, MediaConnectState, MediaDuplexState, MinorDriverVersion, MtuSize, NdisMedium, NdisPhysicalMedium, NetLuid, NetLuidIndex, NotUserRemovable, OperationalStatusDownDefaultPortNotAuthenticated, OperationalStatusDownInterfacePaused, OperationalStatusDownLowPowerState, OperationalStatusDownMediaDisconnected, PnPDeviceID, PromiscuousMode, ReceiveLinkSpeed, State, TransmitLinkSpeed, Virtual, VlanID, WdmInterface, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompNetAdapter.csv -Append -NoTypeInformation

Get-NetIPAddress |Select-Object PrefixOrigin, SuffixOrigin, Type, Store, AddressFamily, AddressState, ifIndex, Caption, Description, ElementName, InstanceID, CommunicationStatus, DetailedStatus, HealthState, InstallDate, Name, OperatingStatus, OperationalStatus, PrimaryStatus, Status, StatusDescriptions, AvailableRequestedStates, EnabledDefault, EnabledState, OtherEnabledState, RequestedState, TimeOfLastStateChange, TransitioningToState, CreationClassName, SystemCreationClassName, SystemName, NameFormat, OtherTypeDescription, ProtocolIFType, ProtocolType, Address, AddressOrigin, AddressType, IPv4Address, IPv6Address, IPVersionSupport, PrefixLength, SubnetMask, InterfaceAlias, InterfaceIndex, IPAddress, PreferredLifetime, SkipAsSource, ValidLifetime, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompNetIP.csv -Append -NoTypeInformation
<#
Get-CimInstance Win32_ComputerSystem |Select-Object AdminPasswordStatus, BootupState, ChassisBootupState, KeyboardPasswordStatus, PowerOnPasswordStatus, PowerSupplyState, PowerState, FrontPanelResetStatus, ThermalState, Status, Name, PowerManagementCapabilities, PowerManagementSupported, Caption, Description, InstallDate, CreationClassName, NameFormat, PrimaryOwnerContact, PrimaryOwnerName, Roles, InitialLoadInfo, LastLoadInfo, ResetCapability, AutomaticManagedPagefile, AutomaticResetBootOption, AutomaticResetCapability, BootOptionOnLimit, BootOptionOnWatchDog, BootROMSupported, BootStatus, ChassisSKUNumber, CurrentTimeZone, DaylightInEffect, DNSHostName, Domain, DomainRole, EnableDaylightSavingsTime, HypervisorPresent, InfraredSupported, Manufacturer, Model, NetworkServerModeEnabled, NumberOfLogicalProcessors, NumberOfProcessors, OEMLogoBitmap, OEMStringArray, PartOfDomain, PauseAfterReset, PCSystemType, PCSystemTypeEx, ResetCount, ResetLimit, SupportContactDescription, SystemFamily, SystemSKUNumber, SystemStartupDelay, SystemStartupOptions, SystemStartupSetting, SystemType, TotalPhysicalMemory, UserName, WakeUpType, Workgroup, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='SerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date} | Export-Csv -Path $DestinationFolder\CompSystem.csv -Append -NoTypeInformation
#>

 #Printers
$Printer = Get-Printer
<#$Printer |Select-Object RenderingMode, PrinterStatus, Type, DeviceType, Caption, Description, ElementName, InstanceID, CommunicationStatus, DetailedStatus, HealthState, InstallDate, Name, OperatingStatus, OperationalStatus, PrimaryStatus, Status, StatusDescriptions, BranchOfficeOfflineLogSizeMB, Comment, ComputerName, Datatype, DefaultJobPriority, DisableBranchOfficeLogging, DriverName, JobCount, KeepPrintedJobs, Location, PermissionSDDL, PortName, PrintProcessor, Priority, Published, SeparatorPageFile, Shared, ShareName, StartTime, UntilTime, WorkflowPolicy, PSComputerName, @{label='ComputerName';e={$ComputerName}}, @{label='SerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date} | Export-Csv -Path $DestinationFolder\CompPrinters.csv -Append -NoTypeInformation;
 #>
 

#Flash
   #Pulls the currently installed version of Flash from the registry.
    #http://www.adobe.com/software/flash/about/?UPCDeviceType=Homepage&UPCLocale=en_US&UPCInstallLocale=en_US&
    $Flash =  Get-ItemProperty 'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
    $Flash = if ([string]::IsNullOrEmpty($Flash.CurrentVersion)) {
                 Write-Output 'NULL'
             }
             else {
                 Write-Output $Flash.CurrentVersion | ForEach-Object {$_ -replace ",", "."}     #Replaces commas “,” with periods “.” for consistency.
             }
        Write-Verbose "Old Flash: $($Flash)"

    $FlashNPAPIKey = 'HKLM:\SOFTWARE\Macromedia\FlashPlayerPlugin'    #NPAPI Flash registry key
    $FlashNPAPITest = Test-Path $FlashNPAPIKey    #Check if it is instlled
    If ($FlashNPAPITest -eq "True") {
            $FlashNPAPI = Get-ItemProperty $FlashNPAPIKey
            Write-Verbose "Flash NPAPI: $($FlashNPAPI.Version)"
        }
        Else {
            $FlashNPAPI = Write-Output 'NULL'
            Write-Verbose "Flash NPAPI: NULL"
        }


    $FlashPPAPIKey = 'HKLM:\SOFTWARE\Macromedia\FlashPlayerPepper'
    $FlashPPAPITest = Test-Path $FlashPPAPIKey
    If ($FlashPPAPITest -eq "True") {
            $FlashPPAPI = Get-ItemProperty $FlashPPAPIKey
            Write-Verbose  "Flash PPAPI (Pepper): $($FlashPPAPI.Version)"
        }
         Else {
            $FlashPPAPI = Write-Output 'NULL'
            Write-Verbose "Flash PPAPI (Pepper): NULL"
        }


    $FlashActiveXKey = 'HKLM:\SOFTWARE\Macromedia\FlashPlayerActiveX'
    $FlashActiveXTest = Test-Path $FlashNPAPIKey
    If($FlashActiveXTest -eq "True") {
            $FlashActiveX = Get-ItemProperty $FlashActiveXKey
            Write-Verbose "Flash ActiveX: $($FlashActiveX.Version)"         
        }
        Else {
            $FlashActiveX = Write-Output 'NULL'
            Write-Verbose "Flash ActiveX: NULL"
        }


#Java
    #OLDer $Java = Get-WmiObject Win32_Product -Filter "Name like 'Java % Update %'" | where {$_.Name -notlike '* Development Kit *'} | Sort-Object Version
    #OLD $Java = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F64180111F0}'    #may need to make the key a variable with *
    
    IF ($system.SystemType -eq "X86-based PC") {
        $JavaKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F*}'    #Use this key if on a 32-bit system
    }
    Else {
        $JavaKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F*}'    #Use this key if on a 64-bit system    
    }

    $JavaTest = Test-Path $JavaKey    #test to see if Java is installed
    If ($JavaTest -eq "True") {    #if it is... 
        $Java = Get-ItemProperty $JavaKey | Where-Object {$_.DisplayName -like 'Java *'}    #Get the properties of the correct registry key
        Write-Verbose "Java Runtime Environment (JRE): $($Java.DisplayVersion)"    #Display the version of JRE to the console
    }
    Else {
        $Java = Write-Output 'NULL'
        Write-Verbose "Java Runtime Environment (JRE): NULL or incorect '*bit' version installed"
    }


#Chrome
    IF ($system.SystemType -eq "X86-based PC") 
    {
	    $ChromeKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
    }
    Else 
    {
        $ChromeKey = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome\'
    }      
    $ChromeTest = Test-Path $ChromeKey
        If ($ChromeTest -eq "True")
        {
            $Chrome = Get-ItemProperty $ChromeKey
            Write-Verbose "Chrome: $($Chrome.Version)" -Verbose         
        } 
        Else 
        {
            $Chrome = Write-Output 'NULL'
            Write-Verbose "Chrome: NULL" -Verbose
        }


#Firefox
    $FirefoxKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
    $Firefox64Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'

    $FirefoxTest = Test-Path $FirefoxKey
    If ($FirefoxTest -eq "True")
    {
        $Firefox = Get-ItemProperty $FirefoxKey
        Write-Verbose "$($Firefox.Displayname)" -Verbose
    } 
    Else 
    {
            $Firefox = 'NULL'
            Write-Verbose "Firefox 32-bit: NULL" -Verbose
    }

    $Firefox64Test = Test-Path $Firefox64Key
    If ($Firefox64Test -eq "True")
    {
        $Firefox64 = Get-ItemProperty $Firefox64Key
        Write-Verbose "$($Firefox64.Displayname)" -Verbose
    } 
    Else 
    {
        $Firefox64 = 'NULL'
        Write-Verbose "Firefox 64-bit: NULL" -Verbose
    }


#Internet Explorer
    $IE = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'

#Adobe Reader
    #$Reader = Get-WmiObject Win32_Product -Filter "Name like '% Reader %'"
    IF ($system.SystemType -eq "X86-based PC")
    {
        $ReaderKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{AC76BA86-7AD7-1*}'
    }
    Else
    {
        $ReaderKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{AC76BA86-7AD7*}'
    }
    $ReaderTest = Test-Path $ReaderKey
        If ($ReaderTest -eq "True") 
        {
            $Reader = Get-ItemProperty $ReaderKey
            Write-Verbose "Adobe Reader: $($Reader.DisplayVersion)" -Verbose
        } 
        Else
        {
            $Reader = Write-Output 'NULL'
            Write-Verbose "Adobe Reader: NULL" -Verbose
        }

#Google Drive
    $GoogleDrive = Get-Process *googledrive*
    If ([string]::IsNullOrEmpty($GoogleDrive)) {
        $GoogleDrive = Write-Output "Stopped"
        Write-Verbose "Googele Drive: Stopped" -Verbose
    }
    Else {
        $GoogleDrive = Write-Output "Running"
        Write-Verbose "Googele Drive: Running" -Verbose
    }


#G Suite Sync
    IF ($system.SystemType -eq "X86-based PC") {
        $GSuiteKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CCE9211C-DF42-46CF-B0C5-4800C4882881}'
    }
    Else{
        $GSuiteKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{CCE9211C-DF42-46CF-B0C5-4800C4882881}'
    }
    $GSuiteTest = Test-Path $GSuiteKey
        If ($GSuiteTest -eq "True") {
            $GSuite = Get-ItemProperty $GSuiteKey
            Write-Verbose "G Suite Sync: $($GSuite.DisplayVersion)"
        } 
        Else {
            $GSuite = Write-Output 'N/A'
            Write-Verbose "G Suite Sync not installed"
        }


#McAfee
    $McAfeeKey = 'HKLM:\SOFTWARE\Wow6432Node\McAfee\Agent\'
    $McAfeeTest = Test-Path $McAfeeKey
        If ($McAfeetest -eq 'True') 
        {
            $McAfeeAgent = (Get-ItemProperty $McAfeeKey).AgentVersion
            Write-Verbose "McAfee Agent: $($McAfeeAgent)" -Verbose
        }
        Else 
        {
            $McAfeeAgent = 'NULL'
            Write-Verbose "McAfee Agent: NULL" -Verbose
        }

#Network
If ($PSVersionTable.PSVersion.Major -gt 4) {
    $EthernetAdapter = Get-NetAdapter -Name Ethernet
    $WiFiAdapter = Get-NetAdapter -Name Wi-Fi

    $EthernetIPv4 = Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4
    $EthernetIPv6 = Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv6
    $WiFiIPv4 = Get-NetIPAddress -InterfaceAlias Wi-Fi -AddressFamily IPv4
    $WiFiIPv6 = Get-NetIPAddress -InterfaceAlias Wi-Fi -AddressFamily IPv6
 }

    $network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
        If ($network.Description -like "*Wireless*") {
            $netAdapter = "Wireless"
        } 
        Else {
            $AdapterType = Get-WmiObject win32_networkadapter -filter "netconnectionstatus = 2" | Select-Object AdapterType | Select-Object -first 1
            $netAdapter =  $AdapterType.AdapterType
        }

    $FirstIP = if ([string]::IsNullOrEmpty($network.IPAddress[0])) {Write-Output 'NULL'} else {Write-Output $network.IPAddress[0]}
    $SecondIP = if ([string]::IsNullOrEmpty($network.IPAddress[1])) {Write-Output 'NULL'} else {Write-Output $network.IPAddress[1]}
    $FirstSub = if ([string]::IsNullOrEmpty($network.IPSubnet[0])) {Write-Output 'NULL'} else {Write-Output $network.IPSubnet[0]}
    $SecondSub = if ([string]::IsNullOrEmpty($network.IPSubnet[1])) {Write-Output 'NULL'} else {Write-Output $network.IPSubnet[1]}

    $WINS = if ([string]::IsNullOrEmpty($network.WINSPrimaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSPrimaryServer}
    $WINSBackup = if ([string]::IsNullOrEmpty($network.WINSSecondaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSSecondaryServer}
    $DNS = if ([string]::IsNullOrEmpty($network.DNSServerSearchOrder[0])) {Write-Output 'NULL'} else {Write-Output $network.DNSServerSearchOrder[0]}
    $DNSBackup = if ([string]::IsNullOrEmpty($network.DNSServerSearchOrder[1])) {Write-Output 'NULL'} else {Write-Output $network.DNSServerSearchOrder[1]}

    
#TeamViewer
    $TeamViewerKey = 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer'
    $TeamViewerTest = Test-Path $TeamViewerKey
        If ($TeamViewerTest -eq "True") {
            $TeamViewerVersion = (Get-ItemProperty $TeamViewerKey).Version
            $TeamViewerID = (Get-ItemProperty $TeamViewerKey).ClientID           
        }
        Else{
            Write-Output "TeamViewer not installed"
        }

        Write-Verbose "TeamViewer Version: $TeamViewerVersion" -Verbose
        Write-Verbose "TeamViewer 14 ID: $TeamViewerID" -Verbose




#Firewall
    $FirewallState = netsh advfirewall show allprofiles | Where-Object {$_ -match "State"} |ForEach-Object {$_ -replace "State                                 ",""}
        $DomainFW = $FirewallState[0]
        $PrivateFW = $FirewallState[1]
        $PublicFW = $FirewallState[2]    

#Storage


$CDisk = Get-Disk -Number 0     #https://docs.microsoft.com/en-us/powershell/module/storage/get-disk?view=win10-ps

$BootDrive = Get-Disk |Where-Object {$_.BootFromDisk -eq $true}

    #$Volume = Get-Volume    #Requires Windows 8 or newer. Using "Get-PSDrive" instead.
    $CDriveModel = ($Win32DiskDrive | Where-Object {$_.deviceID -eq "\\.\PHYSICALDRIVE0"}).Model
    $CDrive = Get-PSDrive -Name C
        $CDriveUsed = $CDrive | ForEach-Object {[math]::Round($_.used / 1GB)}
        $CDriveFree = $CDrive | ForEach-Object {[math]::Round($_.free / 1GB)}
        $CDriveCapacity = $CDrive.Used+$CDrive.Free
            $CDriveCapacity = ForEach-Object {[math]::Round($CDriveCapacity / 1GB)}

        $CDrivePercentUsed = ($CDriveUsed/$CDriveCapacity).ToString("P")

$CMediaType = (Get-CimInstance MSFT_PhysicalDisk -Namespace Root\Microsoft\Windows\Storage |Where-Object {$_.model -eq $CDriveModel}).MediaType
        
        <#Get-Volume -DriveLetter C | select @{L="PercentUsed";E={($_.sizeremaining/$_.size).ToString("P")}}#>
        <#https://blogs.technet.microsoft.com/heyscriptingguy/2014/10/11/weekend-scripter-use-powershell-to-calculate-and-display-percentages/#>


        


#ADD FORMAT TYPE (GPT, MBR, ETC.) FROM GET-DISK TO LOGICAL DIRVES

#Drives
    $LogicalDrives = $Win32DiskDrive | ForEach-Object {
        $disk = $_
        $partitions = "ASSOCIATORS OF " +
        "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
        "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
        Get-WmiObject -Query $partitions | ForEach-Object {
            $partition = $_
            $drives = "ASSOCIATORS OF " +
            "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
            "WHERE AssocClass = Win32_LogicalDiskToPartition"
            Get-WmiObject -Query $drives | ForEach-Object {
                [PSCustomObject]@{
                    Disk                   = $disk.DeviceID;
                    DiskModel              = $disk.Model;
                    Partition              = $partition.Name -replace ",", "";
                    RawSize                = $partition.Size | ForEach-Object { [math]::Round($_ / 1GB, 2) }
                    DriveLetter            = $_.DeviceID
                    VolumeName             = $_.VolumeName
                    Size                   = $_.Size | ForEach-Object { [math]::Round($_ / 1GB, 2) }
                    FreeSpace              = $_.FreeSpace | ForEach-Object { [math]::Round($_ / 1GB, 2) }
                    FileSystem             = $_.FileSystem
                    MaximumComponentLength = $_.MaximumComponentLength
                    MediaType              = $_.MediaType
                    VolumeSerialNumber     = $_.VolumeSerialNumber
                    Partitions             = $disk.Partitions;
                    BytesPerSector         = $disk.BytesPerSector;
                    InterfaceType          = $disk.InterfaceType;
                    SectorsPerTrack        = $disk.SectorsPerTrack;
                    TotalCylinders         = $disk.TotalCylinders;
                    TotalHeads             = $disk.TotalHeads;
                    TotalSectors           = $disk.TotalSectors;
                    TotalTracks            = $disk.TotalTracks;
                    TracksPerCylinder      = $disk.TracksPerCylinder;
                    'ComputerName'         = $ComputerName;
                    'ComputerSerialNumber' = $bios.SerialNumber;
                    'Timestamp'            = $date;
                }
            }
        }
    }
    $LogicalDrives | Export-Csv -Path $DestinationFolder\LogicalDrives.csv -Append -NoTypeInformation

#https://stackoverflow.com/questions/31088930/combine-get-disk-info-and-logicaldisk-info-in-powershell



#BitLocker
$PowerShellAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")     #check if PowerShell is running as an administrator
    #https://superuser.com/questions/749243/detect-if-powershell-is-running-as-administrator
if ($PowerShellAdmin -eq $true) {
    Get-BitLockerVolume |Select-Object ComputerName, MountPoint, EncryptionMethod, AutoUnlockEnabled, AutoUnlockKeyStored, MetadataVersion, VolumeStatus, ProtectionStatus, LockStatus, EncryptionPercentage, WipePercentage, VolumeType, CapacityGB, @{label='CompSerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Export-Csv -Path $DestinationFolder\CompBitLocker.csv -Append -NoTypeInformation

    $FixedDrives = Get-Volume | Where-Object {$_.DriveType -eq "Fixed"}
        If ($FixedDrives.driveletter -eq "D") {
            $DBitLocker = Get-BitLockerVolume -MountPoint D:
            $DBLVolumeStatus = $DBitLocker.VolumeStatus
            $DBLProtectionStatus = $DBitLocker.ProtectionStatus
            $DBLEncryptionPercentage = $DBitLocker.EncryptionPercentage
        }

    $CBitLocker = Get-BitLockerVolume -MountPoint C:
    $CBLVolumeStatus = $CBitLocker.VolumeStatus
    $CBLProtectionStatus = $CBitLocker.ProtectionStatus
    $CBLEncryptionPercentage = $CBitLocker.EncryptionPercentage
}
else{
    Write-Output "skipping BitLocker..."
}

#Video Driver
    

        $AMDVidDriver = $VideoController | Where-Object {$_.Name -like "*AMD*" -or $_.Name -like "*Radeon*"}
        If ([string]::IsNullOrEmpty($AMDVidDriver))    #Sees if an AMD GPU is instlled
        {
            $AMDVidDriver = 'NULL'    #If not, mark as empty
        }
        Else
        {
            
            $AMDVidDriverVersion = $AMDVidDriver | Select-Object DriverVersion -First 1
            $AMDVidDriverName = $AMDVidDriver | Select-Object Name -First 1
            Write-Output "$($AMDVidDriverName.Name)"
            Write-Verbose "AMD Driver: $($AMDVidDriverVersion.DriverVersion)" -Verbose
        }


        
        If ([string]::IsNullOrEmpty($($VideoController | Where-Object {$_.Name -Like "*Intel*"})))    #Sees if an Intel GPU is instlled
        {
            $IntelVidDriver = 'NULL'
        } 
        Else 
        {
            $IntelVidDriver = $VideoController | Where-Object {$_.Name -Like "*Intel*"}
            $IntelVidDriverVersion = $IntelVidDriver | Select-Object DriverVersion -First 1
            $IntelVidDriverName = $IntelVidDriver | Select-Object Name -First 1
            Write-Output "$($IntelVidDriverName.Name)"    #GPU model name
            Write-Verbose "Intel Driver: $($IntelVidDriverVersion.DriverVersion)" -Verbose    #GPU driver version

        }
            
        
        If ([string]::IsNullOrEmpty($($VideoController | Where-Object {$_.Name -Like "*NVIDIA*"})))    #Sees if a NVIDIA GPU is instlled
        {
            $NVIDIAVidDriver = 'NULL'
        }
        Else
        {
            $NVIDIAVidDriver = $VideoController | Where-Object {$_.Name -Like "*NVIDIA*"}
            $NVIDIAVidDriverVersion = $NVIDIAVidDriver | Select-Object DriverVersion -First 1
            $NVIDIAVidDriverName = $NVIDIAVidDriver | Select-Object Name -First 1
            Write-Output "$($NVIDIAVidDriverName.Name)"
            Write-Verbose "NVIDIA Driver: $($NVIDIAVidDriverVersion.DriverVersion)" -Verbose
            
        }


#Microsoft Office 2013
    $Office2013RegKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{90150000-0012-0000-0000-0000000FF1CE}'
    $Office2013Test = Test-Path $Office2013RegKey
        If ($Office2013Test -eq "True") {
            $Office2013 = Get-ItemProperty $Office2013RegKey
            Write-Verbose "Office 2013: $($Office2013.DisplayVersion)"
        } 
        Else {
            $Office2013 = Write-Output 'N/A'
            Write-Verbose "Office 2013 not installed"
        }


#Malwarebytes Anti-Malware
    $MBAMRegKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{35065F43-4BB2-439A-BFF7-0F1014F2E0CD}_is1'
    $MBAMTest = Test-Path $MBAMRegKey
        If ($MBAMTest -eq "True") {
            $MBAM = Get-ItemProperty $MBAMRegKey
            Write-Verbose "Malwarebytes Anti-Malware: $($MBAM.DisplayVersion)"
        } 
        Else {
            $MBAM = Write-Output 'N/A'
            Write-Verbose "Malwarebytes Anti-Malware not installed"
        }


#Account Permissions
    $AdminUsers = net localgroup administrators
    $AdminPrivileges = $AdminUsers -ccontains $env:USERNAME    
        If ($AdminPrivileges -eq "True") 
        {
            Write-Error -Message "Current user has administrator privileges."
        } 
        Else 
        {
            Write-Output "Current user does not have administrator privileges."
        }


#Support Website
    If ($System.Manufacturer -Like "Dell Inc.") {
        $SupportWebsite =  "https://www.dell.com/support/home/us/en/19/product-support/servicetag/$($bios.SerialNumber)/warranty"
    }


#Output
    <#CompHardware#>
    $CompHardware = [PSCustomObject]@{
        'Hostname'          = $ComputerName;
        'SerialNumber'      = $bios.SerialNumber;
        'Manufacturer'      = $System.Manufacturer -replace ",", "";
        'ModelNumber'       = $system.Model -replace ",", ".";
        'EthernetAdapter'   = $EthernetAdapter.InterfaceDescription;
        'EthernetState'     = $EthernetAdapter.Status;
        'EthernetMAC'       = $EthernetAdapter.MacAddress;
        'EthernetSpeed'     = $EthernetAdapter.LinkSpeed;
        'WiFiAdapter'       = $WiFiAdapter.InterfaceDescription;
        'WiFiState'         = $WiFiAdapter.Status;
        'WiFiMAC'           = $WiFiAdapter.MacAddress;
        'WiFiSpeed'         = $WiFiAdapter.LinkSpeed;
        'CPUName'           = $Win32Processor.Name;
        'PhysicalCores'     = $Win32Processor.NumberOfCores;
        'LogicalCores'      = $Win32Processor.NumberOfLogicalProcessors;
        'MaxFrequency'      = $MaxGHz;
        'Memory'            = "$memory GB";
        'AMDGPU'            = $AMDVidDriverName.Name;
        'NVIDIAGPU'         = $NVIDIAVidDriverName.Name;
        'IntelGPU'          = $IntelVidDriverName.Name;
        'PrimaryDriveModel' = $CDriveModel -replace ",", "";
        'MediaType'         = $CMediaType;
        'BusType'           = $CDisk.BusType;
        'Capacity'          = "$CDriveCapacity GB";
        'WindowsKey'        = $ProductKey;
        'OSName'            = $WinOperatingSystem.Caption -replace 'Microsoft ', '';
        'Architecture'      = $system.SystemType;
        'SupportWebsite'    = $SupportWebsite;
        'Timestamp'         = $date;
    }
    Write-Verbose $CompHardware

<# $TestHardwareCSV = Test-Path ".\Computers\CompHardware.csv"
If ($TestHardwareCSV -eq $true) {
    Write-Verbose "Using existing folder: .\Computers\CompHardware.csv" -Verbose
} 
Else {
    New-Item -ItemType File -Path .\Computers -Name CompHardware.csv
}

$GetCompHardware = Get-Content .\Computers\CompHardware.csv | Select-String -Pattern $BIOS.SerialNumber
if ($null -eq $GetCompHardware) { #>
    $CompHardware | Export-Csv -Path $DestinationFolder\CompHardware.csv -Append -NoTypeInformation
<# }
else {
    Write-Verbose "Device already in database. Skipping hardware..."
} #>


<#CompSystem#>
    $CompSystem = [PSCustomObject]@{
        'Hostname'                                  = $ComputerName;
        'SerialNumber'                              = $bios.SerialNumber;
        'EthernetIPv4'                              = $EthernetIPv4;
        'EthtIPv4Prefix'                            = $EthernetIPv4.PrefixLength;
        'EthIPv4PrefixOrigin'                       = $EthernetIPv4.PrefixOrigin;
        'EthernetIPv6'                              = $EthernetIPv6;
        'EthtIPv6Prefix'                            = $EthernetIPv6.PrefixLength;
        'EthtIPv6PrefixOrigin'                      = $EthernetIPv6.PrefixOrigin;
        'WiFiIPv4'                                  = $WiFiIPv4;
        'WiFiIPv4Prefix'                            = $WiFiIPv4.PrefixLength;
        'WiFiIPv4PrefixOrigin'                      = $WiFiIPv4.PrefixOrigin;
        'WiFiIPv6'                                  = $WiFiIPv6;
        'WiFiIPv6Prefix'                            = $WiFiIPv6.PrefixLength;
        'WiFiIPv6PrefixOrigin'                      = $WiFiIPv6.PrefixOrigin;
        'DefaultGateway'                            = $network.DefaultIPGateway[0];
        'PrimaryDNS'                                = $DNS;
        'BackupDNS'                                 = $DNSBackup;
        'Domain'                                    = $system.Domain;
        'FreeMemory'                                = "$FreeMemory GB";
        'MemPctUsed'                                = "$FreeMemoryPercent %";
        'Username'                                  = $user;
        'AdminPrivileges'                           = $AdminPrivileges;
        'DesktopPath'                               = $DesktopPath;
        'TeamViewerVersion'                         = $TeamViewerVersion
        'TeamViewerID'                              = $TeamViewerID;
        'GoogeleDrive'                              = $GoogleDrive;
        'GSuite'                                    = $GSuite.DisplayVersion;
        'DiskUsed'                                  = "$CDriveUsed GB";
        'DiskFree'                                  = "$CDriveFree GB";
        'DiskPctUsed'                               = $CDrivePercentUsed;
        'PartitionStyle'                            = $BootDrive.PartitionStyle;
        'DomainFW'                                  = $DomainFW;
        'PrivateFW'                                 = $PrivateFW;
        'PublicFW'                                  = $PublicFW;
        'C_BitLocker'                               = $CBLProtectionStatus;
        'C_BLVolume'                                = $CBLVolumeStatus;
        'C_BLProtection'                            = $CDBLProtectionStatus;
        'C_BLPct'                                   = $CBLEncryptionPercentage;
        'D_BitLocker'                               = $DBLProtectionStatus;
        'D_BLVolume'                                = $DBLVolumeStatus;
        'D_BLProtection'                            = $DDBLProtectionStatus;
        'D_BLPct'                                   = $DBLEncryptionPercentage;
        'OS_Version'                                = $SoftwareLicensing.Version;
        'OS_Build'                                  = $WinOperatingSystem.BuildNumber;
        'SMBIOS'                                    = $bios.SMBIOSBIOSVersion;
        'BIOS Version'                              = $bios.Version;
        'BIOS Date/Name'                            = $bios.Name;
        'Internet Explorer'                         = $IE.svcVersion;
        'Firefox 32-bit'                            = $Firefox.DisplayVersion;
        'Firefox 64-bit'                            = $Firefox64.DisplayVersion;
        'Chrome'                                    = $Chrome.Version;
        'Flash'                                     = $Flash;
        'Flash NPAPI'                               = $FlashNPAPI.Version;
        'Flash PPAPI'                               = $FlashPPAPI.Version;
        'Java'                                      = $Java.DisplayVersion;
        'Adobe Reader'                              = $Reader.DisplayVersion;
        'PowerShell'                                = $PSVersionTable.PSVersion;
        'AMD Driver'                                = $AMDVidDriverVersion.DriverVersion;
        'NVIDIA Driver'                             = $NVIDIAVidDriverVersion.DriverVersion;
        'Intel Driver'                              = $IntelVidDriverVersion.DriverVersion;
        'McAfee'                                    = $McAfeeAgent;
        'Office2013Name'                            = $Office2013.DisplayName;
        'Office2013Ver'                             = $Office2013.DisplayVersion;
        'MBAM'                                      = $MBAM.DisplayVersion;
        'IP1'                                       = $oct0;
        'IP2'                                       = $oct1;
        'IP3'                                       = $oct2;
        'IP4'                                       = $oct3;
        'Timestamp'                                 = $date;
        'FreePhysicalMemory'                        = $WinOperatingSystem.FreePhysicalMemory;
        'FreeSpaceInPagingFiles'                    = $WinOperatingSystem.FreeSpaceInPagingFiles;
        'FreeVirtualMemory'                         = $WinOperatingSystem.FreeVirtualMemory;
        'OSInstallDate'                             = $WinOperatingSystem.InstallDate;
        'CurrentTimeZone'                           = $WinOperatingSystem.CurrentTimeZone;
        'LastBootUpTime'                            = $WinOperatingSystem.LastBootUpTime;
        'Distributed'                               = $WinOperatingSystem.Distributed;
        'LocalDateTime'                             = $WinOperatingSystem.LocalDateTime;
        'MaxNumberOfProcesses'                      = $WinOperatingSystem.MaxNumberOfProcesses;
        'MaxProcessMemorySize'                      = $WinOperatingSystem.MaxProcessMemorySize;
        'NumberOfLicensedUsers'                     = $WinOperatingSystem.NumberOfLicensedUsers;
        'NumberOfProcesses'                         = $WinOperatingSystem.NumberOfProcesses;
        'NumberOfUsers'                             = $WinOperatingSystem.NumberOfUsers;
        'OSType'                                    = $WinOperatingSystem.OSType;
        'OtherTypeDescription'                      = $WinOperatingSystem.OtherTypeDescription;
        'Caption'                                   = $WinOperatingSystem.Caption;
        'SizeStoredInPagingFiles'                   = $WinOperatingSystem.SizeStoredInPagingFiles;
        'TotalSwapSpaceSize'                        = $WinOperatingSystem.TotalSwapSpaceSize;
        'TotalVirtualMemorySize'                    = $WinOperatingSystem.TotalVirtualMemorySize;
        'TotalVisibleMemorySize'                    = $WinOperatingSystem.TotalVisibleMemorySize;
        'BootDevice'                                = $WinOperatingSystem.BootDevice;
        'BuildType'                                 = $WinOperatingSystem.BuildType;
        'CodeSet'                                   = $WinOperatingSystem.CodeSet;
        'CountryCode'                               = $WinOperatingSystem.CountryCode;
        'CSDVersion'                                = $WinOperatingSystem.CSDVersion;
        'DataExecutionPrevention_32BitApplications' = $WinOperatingSystem.DataExecutionPrevention_32BitApplications;
        'DataExecutionPrevention_Available'         = $WinOperatingSystem.DataExecutionPrevention_Available;
        'DataExecutionPrevention_Drivers'           = $WinOperatingSystem.DataExecutionPrevention_Drivers;
        'DataExecutionPrevention_SupportPolicy'     = $WinOperatingSystem.DataExecutionPrevention_SupportPolicy;
        'Debug'                                     = $WinOperatingSystem.Debug;
        'EncryptionLevel'                           = $WinOperatingSystem.EncryptionLevel;
        'ForegroundApplicationBoost'                = $WinOperatingSystem.ForegroundApplicationBoost;
        'LargeSystemCache'                          = $WinOperatingSystem.LargeSystemCache;
        'Locale'                                    = $WinOperatingSystem.Locale;
        'Manufacturer'                              = $WinOperatingSystem.Manufacturer;
        'MUILanguages'                              = $WinOperatingSystem.MUILanguages;
        'OperatingSystemSKU'                        = $WinOperatingSystem.OperatingSystemSKU;
        'Organization'                              = $WinOperatingSystem.Organization;
        'OSArchitecture'                            = $WinOperatingSystem.OSArchitecture;
        'OSLanguage'                                = $WinOperatingSystem.OSLanguage;
        'OSProductSuite'                            = $WinOperatingSystem.OSProductSuite;
        'PortableOperatingSystem'                   = $WinOperatingSystem.PortableOperatingSystem;
        'Primary'                                   = $WinOperatingSystem.Primary;
        'ProductType'                               = $WinOperatingSystem.ProductType;
        'RegisteredUser'                            = $WinOperatingSystem.RegisteredUser;
        'SerialNumber;'                             = $WinOperatingSystem.SerialNumber;
        'ServicePackMajorVersion'                   = $WinOperatingSystem.ServicePackMajorVersion;
        'ServicePackMinorVersion'                   = $WinOperatingSystem.ServicePackMinorVersion;
        'SuiteMask'                                 = $WinOperatingSystem.SuiteMask;
        'SystemDevice'                              = $WinOperatingSystem.SystemDevice;
        'SystemDirectory'                           = $WinOperatingSystem.SystemDirectory;
        'SystemDrive'                               = $WinOperatingSystem.SystemDrive;
        'WindowsDirectory'                          = $WinOperatingSystem.WindowsDirectory;
    }
    Write-Output $CompSystem
    $CompSystem | Export-Csv -Path $DestinationFolder\CompSystem.csv -Append -NoTypeInformation


    
    
    








<#Inventory Full#>
    $InventoryFull = [PSCustomObject]@{
        'Hostname'            = $ComputerName;
        'Timestamp'           = $date;
        'Serial Number'       = $bios.SerialNumber;
        'Manufacturer'        = $system.Manufacturer;
        'Model Number'        = $system.Model;
        'DHCP'                = $network.DHCPEnabled[0];
        'IP Address'          = $FirstIP;
        'Subnet Mask'         = $FirstSub;
        'Second IP'           = $SecondIP;
        'Second Subnet'       = $SecondSub;
        'Default Gateway'     = $network.DefaultIPGateway[0];
        'Primary DNS'         = $DNS;
        'Backup DNS'          = $DNSBackup;
        'Primary WINS'        = $WINS;
        'Backup WINS'         = $WINSBackup;
        'Domain'              = $system.Domain;
        'MAC Address'         = $network.MACAddress;
        'Network Adapter'     = $network.Description;
        'Adapter Type'        = $netAdapter;
        'CPU Name'            =  $Win32Processor.Name;
        'Physical Cores'      =  $Win32Processor.NumberOfCores;
        'Logical Cores'       = $Win32Processor.NumberOfLogicalProcessors;
        'Max Frequency'       = $MaxGHz;
        'Memory'              = "$memory GB";
        'Free Memory'         = "$FreeMemory GB";
        'Pct Used'            = "$FreeMemoryPercent %";    
        'System Type'         = $system.SystemType
        'Username'            = $user;
        'Admin Privileges'    = $AdminPrivileges;
        'Desktop Path'        = $DesktopPath;
        'TeamViewer'          = $TeamViewerID;
        'AMD GPU'             = $AMDVidDriverName.Name;
        'NVIDIA GPU'          = $NVIDIAVidDriverName.Name;
        'Intel GPU'           = $IntelVidDriverName.Name;
        'Googele Drive'       = $GoogleDrive;
        'Primary Drive Model' = $CDriveModel;
        'Capacity'            = "$CDriveCapacity GB";
        'Used'                = "$CDriveUsed GB";
        'Free'                = "$CDriveFree GB";
        'Percent Used'        = $CDrivePercentUsed;
        'C BitLocker'         = $CBLProtectionStatus;
        'C BL Volume'         = $CBLVolumeStatus;
        'C BL Protection'     = $CDBLProtectionStatus;
        'C BL Percentage'     = $CBLEncryptionPercentage;
        'D BitLocker'         = $DBLProtectionStatus;
        'D BL Volume'         = $DBLVolumeStatus;
        'D BL Protection'     = $DDBLProtectionStatus;
        'D BL Percentage'     = $DBLEncryptionPercentage;
        'BL ID'               = '';
        'BL Key'              = '';
        'Windows Key'         = $ProductKey;
        'OS Name'             = $WinOperatingSystem.Caption -replace 'Microsoft ', '';
        'OS Number'           = $SoftwareLicensing.version;
        'OS Build'            = $WinOperatingSystem.BuildNumber;
        'SMBIOS'              = $bios.SMBIOSBIOSVersion;
        'BIOS Version'        = $bios.Version;
        'BIOS Date/Name'      = $bios.Name;
        'Internet Explorer'   = $IE.svcVersion;
        'Firefox 32-bit'      = $Firefox.DisplayVersion;
        'Firefox 64-bit'      = $Firefox64.DisplayVersion;
        'Chrome'              = $Chrome.Version;
        'Flash'               = $Flash;
        'Flash NPAPI'         = $FlashNPAPI.Version;
        'Flash PPAPI'         = $FlashPPAPI.Version;
        'Java'                = $Java.DisplayVersion;
        'Adobe Reader'        = $Reader.DisplayVersion;
        'PowerShell'          = $PSVersionTable.PSVersion;
        'AMD Driver'          = $AMDVidDriverVersion.DriverVersion;
        'NVIDIA Driver'       = $NVIDIAVidDriverVersion.DriverVersion;
        'Intel Driver'        = $IntelVidDriverVersion.DriverVersion;
        'McAfee'              = $McAfeeAgent;
        'IP1'                 = $oct0;
        'IP2'                 = $oct1;
        'IP3'                 = $oct2;
        'IP4'                 = $oct3;
    }
    $InventoryFull | Export-Csv -Path $DestinationFolder\InventoryFull.csv -Append -NoTypeInformation


#Apps
    $32bit = "32-bit"
    $GetApps32bit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $apps32bit = $GetApps32bit | Select-Object displayname, displayversion, @{label='Bit';e={$32bit}}, @{label='ComputerName';e={$ComputerName}}, @{label='SerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Sort-object -Property DisplayName
    $apps32bit | Export-Csv -Path $DestinationFolder\Apps.csv -Append -NoTypeInformation

    $64bit = "64-bit"
    $GetApps64bit = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' 
    $apps64bit = $GetApps64bit | Select-Object displayname, displayversion, @{label='Bit';e={$64bit}}, @{label='ComputerName';e={$ComputerName}}, @{label='SerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}} | Sort-object -Property DisplayName
    $apps64bit | Export-Csv -Path $DestinationFolder\Apps.csv -Append -NoTypeInformation

#Printers
    $CompPrinters = $Printer | Select-Object Name, DriverName, PortName, Shared, @{label='ComputerName';e={$ComputerName}}, @{label='SerialNumber';e={$bios.SerialNumber}}, @{label='Timestamp';e={$Date}}
    $CompPrinters | Export-Csv -Path $DestinationFolder\Printers.csv -Append -NoTypeInformation

# remove quotes
    foreach ($file in Get-ChildItem $DestinationFolder\*.csv)    #Selects the files
    {
        (Get-Content $file) -replace '"','' | Set-Content $file    #Replaces quotes with a blank space
        (Get-Content $file) -replace "VMware, Inc.","VMware Inc." | Set-Content $file   #remove once NetAdapter is in table object
    }

# #Errors
#     $LogFile = "$DestinationFolder\details\log.txt"
#         Get-Date | Out-File $LogFile -Append
#         $ComputerName | Out-File $LogFile -Append
#         #$Error | Out-File $LogFile -Append
#         $erFlash | Out-File $LogFile -Append
#         $erJava | Out-File $LogFile -Append
}


Get-Inventory -DestinationFolder $DestinationFolder -Verbose