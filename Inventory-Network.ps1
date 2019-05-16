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

    $System = Get-WmiObject Win32_ComputerSystem
    $ComputerName = hostname
    $SoftwareLicensing = Get-WmiObject SoftwareLicensingService


#Date
    $Date =  Get-Date -format s
    $DateReadable = Get-Date -Format g


#ID
    $ipID = ipconfig | Where-Object {$_ -match "IPv4 Address"} | ForEach-Object{$_.Split(":")[1]}
    $oct0 = $ipID.trim().Split(".")[0]
    $oct1 = $ipID.trim().Split(".")[1]
    $oct2 = $ipID.trim().Split(".")[2]
    $oct3 = $ipID.trim().Split(".")[3]


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
    If ([string]::IsNullOrEmpty($GoogleDrive)) 
    {
        $GoogleDrive = Write-Output "Stopped"
        Write-Verbose "Googele Drive: Stopped" -Verbose
    }
    Else
    {
        $GoogleDrive = Write-Output "Running"
        Write-Verbose "Googele Drive: Running" -Verbose
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
    $TeamViewerKey = 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version9'
    $TeamViewerTest = Test-Path $TeamViewerKey
        If ($TeamViewerTest -eq "True") 
        {
            $TeamViewer = Get-ItemProperty $TeamViewerKey
            Write-Verbose "TeamViewer: $($TeamViewer.ClientID)" -Verbose
        } 
        Else
        {
            Write-Output "TeamViewer: NULL"
        }      

#System
    $os = Get-WmiObject Win32_operatingSystem
        Write-Output "Windows: $($SoftwareLicensing.Version)"
        $ProductKey = $SoftwareLicensing.OA3xOriginalProductKey 
        Write-Verbose "Key: $ProductKey" -Verbose

    $CPU = Get-WmiObject Win32_Processor     #Gets information on the CPU
        Write-Output "CPU: $($CPU.Name)"
        $MaxGHz = $CPU | ForEach-Object {[math]::Round($_.MaxClockSpeed / 10)}    #Rounds the clock speed to go from MHz to GHz.
        $MaxGHz = "$($MaxGHz / 100) GHz"    #Adds the decimal place and GHz label.
        

    $memory = Get-WmiObject Win32_computersystem | ForEach-Object {[math]::round($_.totalPhysicalMemory / 1GB)}   #Displays the amount of system memory rounded to the nearest gigabyte.
        Write-Output "RAM: $($memory) GB"
       
        $FreeMemory = [math]::Round($os.FreePhysicalMemory/1mb,2)
        $FreeMemoryPercent = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)

    $bios = Get-WmiObject Win32_bios
    $user = $env:username
    $DesktopPath = [Environment]::GetFolderPath("Desktop")


#Firewall
    $FirewallState = netsh advfirewall show allprofiles | Where-Object {$_ -match "State"} |ForEach-Object {$_ -replace "State                                 ",""}
        $DomainFW = $FirewallState[0]
        $PrivateFW = $FirewallState[1]
        $PublicFW = $FirewallState[2]

#Printers
    If ($PSVersionTable.PSVersion.Major -gt 4) {
        $Printer = Get-Printer
    }
    

#Storage
$CDisk = Get-Disk -Number 0     #https://docs.microsoft.com/en-us/powershell/module/storage/get-disk?view=win10-ps

    #$Volume = Get-Volume    #Requires Windows 8 or newer. Using "Get-PSDrive" instead.
    $DiskDrives = Get-WMIObject Win32_DiskDrive
    $CDriveModel = ($DiskDrives | Where-Object {$_.deviceID -eq "\\.\PHYSICALDRIVE0"}).Model
    $CDrive = Get-PSDrive -Name C
        $CDriveUsed = $CDrive | ForEach-Object {[math]::Round($_.used / 1GB)}
        $CDriveFree = $CDrive | ForEach-Object {[math]::Round($_.free / 1GB)}
        $CDriveCapacity = $CDrive.Used+$CDrive.Free
            $CDriveCapacity = ForEach-Object {[math]::Round($CDriveCapacity / 1GB)}

        $CDrivePercentUsed = ($CDriveUsed/$CDriveCapacity).ToString("P")

$CMediaType = (Get-CimInstance MSFT_PhysicalDisk -Namespace Root\Microsoft\Windows\Storage |Where-Object {$_.model -eq $CDriveModel}).MediaType
        
        <#Get-Volume -DriveLetter C | select @{L="PercentUsed";E={($_.sizeremaining/$_.size).ToString("P")}}#>
        <#https://blogs.technet.microsoft.com/heyscriptingguy/2014/10/11/weekend-scripter-use-powershell-to-calculate-and-display-percentages/#>



#BitLocker
$PowerShellAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")     #check if PowerShell is running as an administrator
    #https://superuser.com/questions/749243/detect-if-powershell-is-running-as-administrator
if ($PowerShellAdmin -eq $true) {
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
    $VidDriver = Get-WmiObject win32_VideoController

        $AMDVidDriver = $VidDriver | Where-Object {$_.Name -like "*AMD*" -or $_.Name -like "*Radeon*"}
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


        
        If ([string]::IsNullOrEmpty($($VidDriver | Where-Object {$_.Name -Like "*Intel*"})))    #Sees if an Intel GPU is instlled
        {
            $IntelVidDriver = 'NULL'
        } 
        Else 
        {
            $IntelVidDriver = $VidDriver | Where-Object {$_.Name -Like "*Intel*"}
            $IntelVidDriverVersion = $IntelVidDriver | Select-Object DriverVersion -First 1
            $IntelVidDriverName = $IntelVidDriver | Select-Object Name -First 1
            Write-Output "$($IntelVidDriverName.Name)"    #GPU model name
            Write-Verbose "Intel Driver: $($IntelVidDriverVersion.DriverVersion)" -Verbose    #GPU driver version

        }
            
        
        If ([string]::IsNullOrEmpty($($VidDriver | Where-Object {$_.Name -Like "*NVIDIA*"})))    #Sees if a NVIDIA GPU is instlled
        {
            $NVIDIAVidDriver = 'NULL'
        }
        Else
        {
            $NVIDIAVidDriver = $VidDriver | Where-Object {$_.Name -Like "*NVIDIA*"}
            $NVIDIAVidDriverVersion = $NVIDIAVidDriver | Select-Object DriverVersion -First 1
            $NVIDIAVidDriverName = $NVIDIAVidDriver | Select-Object Name -First 1
            Write-Output "$($NVIDIAVidDriverName.Name)"
            Write-Verbose "NVIDIA Driver: $($NVIDIAVidDriverVersion.DriverVersion)" -Verbose
            
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

#Destination Folder
    $DestinationFolderPath = Test-Path $DestinationFolder
        If ($DestinationFolderPath -eq 'True') 
        {
            Write-Verbose "Using existing folder: $($DestinationFolder)" -Verbose
        } 
        Else 
        {
            mkdir "$($DestinationFolder)"
        }

#Output
<#CompHardware#>
$CompHardware = [PSCustomObject]@{
    'Hostname' = $ComputerName;
    'SerialNumber' = $bios.SerialNumber;
    'Manufacturer' = $System.Manufacturer -replace ",", "";
    'ModelNumber' = $system.Model -replace ",", ".";
    'EthernetAdapter' = $EthernetAdapter.InterfaceDescription;
    'EthernetState' = $EthernetAdapter.Status;
    'EthernetMAC' = $EthernetAdapter.MacAddress;
    'EthernetSpeed' = $EthernetAdapter.LinkSpeed;
    'WiFiAdapter' = $WiFiAdapter.InterfaceDescription;
    'WiFiState' = $WiFiAdapter.Status;
    'WiFiMAC' = $WiFiAdapter.MacAddress;
    'WiFiSpeed' = $WiFiAdapter.LinkSpeed;
    'CPUName' = $CPU.Name;
    'PhysicalCores' = $CPU.NumberOfCores;
    'LogicalCores' = $CPU.NumberOfLogicalProcessors;
    'MaxFrequency' = $MaxGHz;
    'Memory' = "$memory GB";
    'Username' = $user;
    'AdminPrivileges' = $AdminPrivileges;
    'DesktopPath' = $DesktopPath;
    'TeamViewer' = $TeamViewer.ClientID;
    'AMDGPU' = $AMDVidDriverName.Name;
    'NVIDIAGPU' = $NVIDIAVidDriverName.Name;
    'IntelGPU' = $IntelVidDriverName.Name;
    'PrimaryDriveModel' = $CDriveModel -replace ",", "";
    'MediaType' = $CMediaType;
    'BusType' = $CDisk.BusType;
    'Capacity' = "$CDriveCapacity GB";
    'WindowsKey' = $ProductKey;
    'OSName' = $os.Caption -replace 'Microsoft ','';
    'Architecture' = $system.SystemType
    'Timestamp' = $date;
}
Write-Output $CompHardware
$CompHardware | Export-Csv -Path $DestinationFolder\CompHardware.csv -Append -NoTypeInformation

<#CompSystem#>
$CompSystem = [PSCustomObject]@{
    'Hostname' = $ComputerName;
    'SerialNumber' = $bios.SerialNumber;
    'EthernetIPv4' = $EthernetIPv4;
    'EthtIPv4Prefix' = $EthernetIPv4.PrefixLength;
    'EthIPv4PrefixOrigin' = $EthernetIPv4.PrefixOrigin;
    'EthernetIPv6' = $EthernetIPv6;
    'EthtIPv6Prefix' = $EthernetIPv6.PrefixLength;
    'EthtIPv6PrefixOrigin' = $EthernetIPv6.PrefixOrigin;
    'WiFiIPv4' = $WiFiIPv4;
    'WiFiIPv4Prefix' = $WiFiIPv4.PrefixLength;
    'WiFiIPv4PrefixOrigin' = $WiFiIPv4.PrefixOrigin;
    'WiFiIPv6' = $WiFiIPv6;
    'WiFiIPv6Prefix' = $WiFiIPv6.PrefixLength;
    'WiFiIPv6PrefixOrigin' = $WiFiIPv6.PrefixOrigin;
    'DefaultGateway' = $network.DefaultIPGateway[0];
    'PrimaryDNS' = $DNS;
    'BackupDNS' = $DNSBackup;
    'Domain' = $system.Domain;
    'FreeMemory' = "$FreeMemory GB";
    'MemPctUsed' = "$FreeMemoryPercent %";
    'Username' = $user;
    'AdminPrivileges' = $AdminPrivileges;
    'DesktopPath' = $DesktopPath;
    'TeamViewer' = $TeamViewer.ClientID;
    'GoogeleDrive' = $GoogleDrive;
    'DiskUsed' = "$CDriveUsed GB";
    'DiskFree' = "$CDriveFree GB";
    'DiskPctUsed' = $CDrivePercentUsed;
    'DomainFW' = $DomainFW;
    'PrivateFW' = $PrivateFW;
    'PublicFW' = $PublicFW;
    'C_BitLocker' = $CBLProtectionStatus;
    'C_BLVolume' = $CBLVolumeStatus;
    'C_BLProtection' = $CDBLProtectionStatus;
    'C_BLPct' = $CBLEncryptionPercentage;
    'D_BitLocker' = $DBLProtectionStatus;
    'D_BLVolume' = $DBLVolumeStatus;
    'D_BLProtection' = $DDBLProtectionStatus;
    'D_BLPct' = $DBLEncryptionPercentage;
    'OS Number' = $SoftwareLicensing.version;
    'OS Build' = $os.BuildNumber;
    'SMBIOS' = $bios.SMBIOSBIOSVersion;
    'BIOS Version' = $bios.Version;
    'BIOS Date/Name' = $bios.Name;
    'Internet Explorer' = $IE.svcVersion;
    'Firefox 32-bit' = $Firefox.DisplayVersion;
    'Firefox 64-bit' = $Firefox64.DisplayVersion;
    'Chrome' = $Chrome.Version;
    'Flash' = $Flash;
    'Flash NPAPI' = $FlashNPAPI.Version;
    'Flash PPAPI' = $FlashPPAPI.Version;
    'Java' = $Java.DisplayVersion;
    'Adobe Reader' = $Reader.DisplayVersion;
    'PowerShell' = $PSVersionTable.PSVersion;
    'AMD Driver' = $AMDVidDriverVersion.DriverVersion;
    'NVIDIA Driver' = $NVIDIAVidDriverVersion.DriverVersion;
    'Intel Driver' = $IntelVidDriverVersion.DriverVersion;
    'McAfee' = $McAfeeAgent;
    'IP1' = $oct0;
    'IP2' = $oct1;
    'IP3' = $oct2;
    'IP4' = $oct3;
    'Timestamp' = $date;
}
Write-Output $CompSystem
$CompSystem | Export-Csv -Path $DestinationFolder\CompSystem.csv -Append -NoTypeInformation

    <#Inventory Full#>
            $InventoryFull = [PSCustomObject]@{
                'Hostname' = $ComputerName;
                'Timestamp' = $date;
                'Serial Number' = $bios.SerialNumber;
                'Manufacturer' = $system.Manufacturer;
                'Model Number' = $system.Model;
                'DHCP' = $network.DHCPEnabled[0];
                'IP Address' = $FirstIP;
                'Subnet Mask' = $FirstSub;
                'Second IP' = $SecondIP;
                'Second Subnet' = $SecondSub;
                'Default Gateway' = $network.DefaultIPGateway[0];
                'Primary DNS' = $DNS;
                'Backup DNS' = $DNSBackup;
                'Primary WINS' = $WINS;
                'Backup WINS' = $WINSBackup;
                'Domain' = $system.Domain;
                'MAC Address' = $network.MACAddress;
                'Network Adapter' = $network.Description;
                'Adapter Type' = $netAdapter;
                'CPU Name' = $CPU.Name;
                'Physical Cores' = $CPU.NumberOfCores;
                'Logical Cores' = $CPU.NumberOfLogicalProcessors;
                'Max Frequency' = $MaxGHz;
                'Memory' = "$memory GB";
                'Free Memory' = "$FreeMemory GB";
                'Pct Used' = "$FreeMemoryPercent %";    
                'System Type' = $system.SystemType
                'Username' = $user;
                'Admin Privileges' = $AdminPrivileges;
                'Desktop Path' = $DesktopPath;
                'TeamViewer' = $TeamViewer.ClientID;
                'AMD GPU' = $AMDVidDriverName.Name;
                'NVIDIA GPU' = $NVIDIAVidDriverName.Name;
                'Intel GPU' = $IntelVidDriverName.Name;
                'Googele Drive' = $GoogleDrive;
                'Primary Drive Model' = $CDriveModel;
                'Capacity' = "$CDriveCapacity GB";
                'Used' = "$CDriveUsed GB";
                'Free' = "$CDriveFree GB";
                'Percent Used' = $CDrivePercentUsed;
                'C BitLocker' = $CBLProtectionStatus;
                'C BL Volume' = $CBLVolumeStatus;
                'C BL Protection' = $CDBLProtectionStatus;
                'C BL Percentage' = $CBLEncryptionPercentage;
                'D BitLocker' = $DBLProtectionStatus;
                'D BL Volume' = $DBLVolumeStatus;
                'D BL Protection' = $DDBLProtectionStatus;
                'D BL Percentage' = $DBLEncryptionPercentage;
                'BL ID' = '';
                'BL Key' = '';
                'Windows Key' = $ProductKey;
                'OS Name' = $os.Caption -replace 'Microsoft ','';
                'OS Number' = $SoftwareLicensing.version;
                'OS Build' = $os.BuildNumber;
                'SMBIOS' = $bios.SMBIOSBIOSVersion;
                'BIOS Version' = $bios.Version;
                'BIOS Date/Name' = $bios.Name;
                'Internet Explorer' = $IE.svcVersion;
                'Firefox 32-bit' = $Firefox.DisplayVersion;
                'Firefox 64-bit' = $Firefox64.DisplayVersion;
                'Chrome' = $Chrome.Version;
                'Flash' = $Flash;
                'Flash NPAPI' = $FlashNPAPI.Version;
                'Flash PPAPI' = $FlashPPAPI.Version;
                'Java' = $Java.DisplayVersion;
                'Adobe Reader' = $Reader.DisplayVersion;
                'PowerShell' = $PSVersionTable.PSVersion;
                'AMD Driver' = $AMDVidDriverVersion.DriverVersion;
                'NVIDIA Driver' = $NVIDIAVidDriverVersion.DriverVersion;
                'Intel Driver' = $IntelVidDriverVersion.DriverVersion;
                'McAfee' = $McAfeeAgent;
                'IP1' = $oct0;
                'IP2' = $oct1;
                'IP3' = $oct2;
                'IP4' = $oct3;
            }
            $InventoryFull | Export-Csv -Path $DestinationFolder\InventoryFull.csv -Append -NoTypeInformation
            
    <#Inventory Small#>   
            $InventorySmall = [PSCustomObject]@{
                'Timestamp' = $date;
                'User Name' = $user;
                'Employees' = $user;
                'Status' = '';
                'Tag' = '';
                'Date Checked' = $DateReadable;
                'Hostname'= $ComputerName;
                'Asset' = 'Laptop';
                'Model Name' = $system.Model;
                'Category' = '';
                'Serial Number' = $bios.SerialNumber;
                'OS' = $os.Caption -replace 'Microsoft ','';
                'CPU Name' = $CPU.Name;
                'Memory' = "$memory GB";
                'Storage' = "$CDriveCapacity GB";
                'MAC Address' = $network.MACAddress;
                'TeamViewer' = $TeamViewer.ClientID;
                'Google Drive' = $GoogleDrive;
                'C Encrypted' = $CBLVolumeStatus;
                'D Encrypted' = $DBLVolumeStatus;
                'Date Deployed' = '';
                'Special Programs' = '';
                'Location' = '';
            }
            $InventorySmall | Export-Csv -Path $DestinationFolder\InventorySmall.csv -Append -NoTypeInformation

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
    $CompPrinters | Export-Csv -Path $DestinationFolder\CompPrinters.csv -Append -NoTypeInformation

# remove quotes
    foreach ($file in Get-ChildItem $DestinationFolder\*.csv)    #Selects the files
    {
        (Get-Content $file) -replace '"','' | Set-Content $file    #Replaces quotes with a blank space
    }

# #Errors
#     $LogFile = "$DestinationFolder\details\log.txt"
#         Get-Date | Out-File $LogFile -Append
#         $ComputerName | Out-File $LogFile -Append
#         #$Error | Out-File $LogFile -Append
#         $erFlash | Out-File $LogFile -Append
#         $erJava | Out-File $LogFile -Append
}


Get-Inventory -DestinationFolder $DestinationFolder