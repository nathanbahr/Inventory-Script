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
    $DateRegular = Get-Date
    $DateReadable = Get-Date -Format g
    $Timestamp = Get-Date -Format o | ForEach-Object {$_ -replace ":", "."}



#ID
    $ipID = ipconfig | Where-Object {$_ -match "IPv4 Address"} | ForEach-Object{$_.Split(":")[1]}
    $oct0 = $ipID.trim().Split(".")[0]
    $oct1 = $ipID.trim().Split(".")[1]
    $oct2 = $ipID.trim().Split(".")[2]
    $oct3 = $ipID.trim().Split(".")[3]
    $id = "$($oct2)$($oct3)"




#Flash
   #Pulls the currently installed version of Flash from the registry.
    #http://www.adobe.com/software/flash/about/?UPCDeviceType=Homepage&UPCLocale=en_US&UPCInstallLocale=en_US&
    $Flash =  Get-ItemProperty 'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
    $Flash = if ([string]::IsNullOrEmpty($Flash.CurrentVersion))
             {
                 Write-Output 'NULL'
             }
             else 
             {
                 Write-Output $Flash.CurrentVersion | ForEach-Object {$_ -replace ",", "."}     #Replaces commas “,” with periods “.” for consistency.
             }
        Write-Verbose "Old Flash: $($Flash)" -Verbose

    $FlashNPAPIKey = 'HKLM:\SOFTWARE\Macromedia\FlashPlayerPlugin'    #NPAPI Flash registry key
    $FlashNPAPITest = Test-Path $FlashNPAPIKey    #Check if it is instlled
    If ($FlashNPAPITest -eq "True")
        {
            $FlashNPAPI = Get-ItemProperty $FlashNPAPIKey
            #Write-Output $FlashNPAPI
            Write-Verbose "Flash NPAPI: $($FlashNPAPI.Version)" -Verbose
        }
        Else
        {
            $FlashNPAPI = Write-Output 'NULL'
            Write-Verbose "Flash NPAPI: NULL" -Verbose
        }


    $FlashPPAPIKey = 'HKLM:\SOFTWARE\Macromedia\FlashPlayerPepper'
    $FlashPPAPITest = Test-Path $FlashPPAPIKey
    If ($FlashPPAPITest -eq "True")
        {
            $FlashPPAPI = Get-ItemProperty $FlashPPAPIKey
            #Write-Output $FlashPPAPI
            Write-Verbose  "Flash PPAPI (Pepper): $($FlashPPAPI.Version)" -Verbose
        }
         Else
        {
            $FlashPPAPI = Write-Output 'NULL'
            Write-Verbose "Flash PPAPI (Pepper): NULL" -Verbose
        }


    $FlashActiveXKey = 'HKLM:\SOFTWARE\Macromedia\FlashPlayerActiveX'
    $FlashActiveXTest = Test-Path $FlashNPAPIKey
    If($FlashActiveXTest -eq "True")
        {
            $FlashActiveX = Get-ItemProperty $FlashActiveXKey
            #Write-Output $FlashActiveX
            Write-Verbose "Flash ActiveX: $($FlashActiveX.Version)" -Verbose           
        }
        Else
        {
            $FlashActiveX = Write-Output 'NULL'
            Write-Verbose "Flash ActiveX: NULL" -Verbose
        }
        


    #Get newest version number
    $TestFlashVersion = Test-Path .\NewestFlash.txt
        If ($TestFlashVersion -like "False")
        {
            New-Item .\NewestFlash.txt
        }
    $NewestFlashFile = Get-ItemProperty .\NewestFlash.txt    #Find the date the file was last modified
    $FlashFileDiffernce = $NewestFlashFile.LastWriteTime-$DateRegular    #Subtract the file date from the current date/time.
    If ($FlashFileDiffernce.Days*-1 -gt 1 -and $PSVersionTable.PSVersion.Major -gt 2)    #Invoke-WebRequest requires PowerShell version 3+.
    {
        #Is Flash updated? 
        $adobecom = Invoke-WebRequest "https://get.adobe.com/flashplayer/"                                                         #Check Adobe's website for the latest version number.
        $NewestFlash = $adobecom.AllElements | Where-Object {$_.InnerHtml -like "version *"} | Select-Object innerHTML -First 1    #Select the version number from the webpage.
            Write-Output $NewestFlash.innerHTML > .\NewestFlash.txt                                                                #Write it to a file.
            (Get-Content .\NewestFlash.txt) -replace 'Version ','' | ForEach-Object {$_.TrimEnd()} | Set-Content .\NewestFlash.txt        #Cleanup the output and make it ready to be read.
    }
    Else 
    {
        #
        Write-Verbose "Reading plug-in version from file..." -Verbose
    }
    #run for PowerShell version 2:


        $NewestFlash = Get-Content .\NewestFlash.txt
        If ($FlashNPAPI.version -NotLike $NewestFlash) 
        {
            Write-Error -ErrorVariable erFlash -Message "Flash needs to be updated: $($FlashNPAPI.version) not $NewestFlash"

                #Options menu
                    $title = "Update Flash"
                    $message = "Do you want to update flash to $($NewestFlash)?"

                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                        "Downloads and installs the latest version of Flash."

                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                        "Skips updating Flash."

                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

		        #Set as '$result' to prompt user. 
                #Set as '1' to skip.
                    $result = 1
                    #$result = $host.ui.PromptForChoice($title, $message, $options, 1)

                    switch ($result)
                    {
                        0 
                        {
			            <#    $FlashInstallers = Get-ChildItem ".\flash\flashplayer*install.exe"	
                            ForEach-Object ($Installer in $FlashInstallers) 
                            {
                                Copy-Item $Installer $env:TEMP
                                Start-Process $Installer -Wait
                            }
                            #clean up
                            Remove-Item "$env:TEMP\flashplayer*install.exe"
                        #>       
                        }
                        1 
                        {
                            "Skipping..."
                        }
                    }
            } 
        Else 
        {
            Write-Verbose "Flash is up-to-date: $($FlashNPAPI.Version)" -Verbose
        }


#Java
    #OLDer $Java = Get-WmiObject Win32_Product -Filter "Name like 'Java % Update %'" | where {$_.Name -notlike '* Development Kit *'} | Sort-Object Version
    #OLD $Java = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F64180111F0}'    #may need to make the key a variable with *
    
    IF ($system.SystemType -eq "X86-based PC")   
    {
        $JavaKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F*}'    #Use this key if on a 32-bit system
    }
    Else
    {
        $JavaKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{26A24AE4-039D-4CA4-87B4-2F*}'    #Use this key if on a 64-bit system    
    }
    $JavaTest = Test-Path $JavaKey    #test to see if Java is installed
    If ($JavaTest -eq "True")    #if it is...
    {
        $Java = Get-ItemProperty $JavaKey | Where-Object {$_.DisplayName -like 'Java *'}    #Get the properties of the correct registry key
        Write-Verbose "Java Runtime Environment (JRE): $($Java.DisplayVersion)" -Verbose    #Display the version of JRE to the console
    }
    Else
    {
        $Java = Write-Output 'NULL'
        Write-Verbose "Java Runtime Environment (JRE): NULL or incorect '*bit' version installed" -Verbose
    }
        
        $TestJavaVersion = Test-Path .\NewestJava.txt
        If ($TestJavaVersion -like "False")
        {
            New-Item .\NewestJava.txt
        }
        $NewestJavaFile = Get-ItemProperty .\NewestJava.txt
        $JavaFileDifference = $NewestJavahFile.LastWriteTime-$DateRegular
        If ($javahFileDiffernce.Days*-1 -gt 1 -and $PSVersionTable.PSVersion.Major -gt 2)
        {
            #Is Java updated?
            $javacom = Invoke-WebRequest "http://www.java.com/en/download/"
            $NewestJava = $javacom.AllElements | Where-Object {$_.InnerHtml -like "Version * Update *"} | Select-Object innerHTML -First 1
                Write-Output $NewestJava.innerHTML > .\NewestJava.txt
                
                (Get-Content .\NewestJava.txt) -replace 'Version','Java' | ForEach-Object {$_.TrimEnd()} | Set-Content .\NewestJava.txt    #Replaces the word 'Version' that is pulled from the web page to 'Java' to match what is in WMI.
        }
        Else
        {
            Write-Verbose "Reading plug-in version from file..." -Verbose
        }

      #removes 64-bit from the Java name so just the version is compared.
        $JavaName = $Java.DisplayName -replace "\(64-bit\)","" | ForEach-Object {$_.TrimEnd()}
        $NewestJava = (Get-Content .\NewestJava.txt)
        
        If ($JavaName -NotLike $NewestJava) 
        {
            Write-Error -Message "Java needs to be updated: $JavaName not $NewestJava"

            #Options menu
                $title = "Update Java"
                $message = "Do you want to update Java to $($NewestJava + "?")"

                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                    "Downloads and installs the latest version of Java."

                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                    "Skips updating Java."

                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	
	        #set as '$result to prompt user. Set as '1' to skip.
                $result = 1 
                #$result = $host.ui.PromptForChoice($title, $message, $options, 1)                     
                 
                switch ($result)
                {
                    0 
                    {   
                        $JavaIntaller = '.\java\'                          
                        if ($system.SystemType -eq "x64-based PC") 
                        {
                            Start-Process .\java\jxpiinstall.exe -Wait
                        }
                        else 
                        {
                            Start-Process .\java\jxpiinstall.exe -Wait
                        }
                           
                    }
                    1 
                    {
                        Write-Verbose "Skipping..."
                    }
                } 
                
            } 
        else 
        {
            Write-Verbose "Java is up-to-date: $($Java.DisplayName)" -Verbose
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


<#
        If ($FirefoxVersion -NotLike "52.0.2") 
        {
            $FirefoxPath = $Firefox.DisplayIcon -replace ",0",""    #Sets the path to Firefox from the registry.
            Start-Process $FirefoxPath     #Opens Firefox to manually run the built-in auto update.
        }
#>

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
    $network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
        If ($network.Description -like "*Wireless*")
        {
            $netAdapter = "Wireless"
        } 
        Else 
        {
            $AdapterType = Get-WmiObject win32_networkadapter -filter "netconnectionstatus = 2" | select AdapterType | Select -first 1
            $netAdapter =  $AdapterType.AdapterType
        }
    $ipconfig = ipconfig /all
    $route = route print

    $FirstIP = if ([string]::IsNullOrEmpty($network.IPAddress[0])) {Write-Output 'NULL'} else {Write-Output $network.IPAddress[0]}
    $SecondIP = if ([string]::IsNullOrEmpty($network.IPAddress[1])) {Write-Output 'NULL'} else {Write-Output $network.IPAddress[1]}
    $FirstSub = if ([string]::IsNullOrEmpty($network.IPSubnet[0])) {Write-Output 'NULL'} else {Write-Output $network.IPSubnet[0]}
    $SecondSub = if ([string]::IsNullOrEmpty($network.IPSubnet[1])) {Write-Output 'NULL'} else {Write-Output $network.IPSubnet[1]}
    $WINS = if ([string]::IsNullOrEmpty($network.WINSPrimaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSPrimaryServer}
    $WINSBackup = if ([string]::IsNullOrEmpty($network.WINSSecondaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSSecondaryServer}
    $DNS = if ([string]::IsNullOrEmpty($network.DNSServerSearchOrder[0])) {Write-Output 'NULL'} else {Write-Output $network.DNSServerSearchOrder[0]}
    $DNSBackup = if ([string]::IsNullOrEmpty($network.DNSServerSearchOrder[1])) {Write-Output 'NULL'} else {Write-Output $network.DNSServerSearchOrder[1..4]}

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

    $CPU = Get-WmiObject Win32_Processor     #Gets information on the CPU
        Write-Output "CPU: $($CPU.Name)"

        $MaxMHz = ((Get-WmiObject Win32_Processor).MaxClockSpeed)    #Gets the maximum clock speed in MHz.
        $MaxGHz = $CPU | ForEach-Object {[math]::Round($_.MaxClockSpeed / 10)}    #Rounds the clock speed to go from MHz to GHz.
        $MaxGHz = "$($MaxGHz / 100) GHz"    #Adds the decimal place and GHz label.
        

    $memory = Get-WmiObject Win32_computersystem | ForEach-Object {[math]::round($_.totalPhysicalMemory / 1GB)}   #Displays the amount of system memory rounded to the nearest gigabyte.
        Write-Output "RAM: $($memory) GB"
       
        $FreeMemory = [math]::Round($os.FreePhysicalMemory/1mb,2)
        $FreeMemoryPercent = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)

    $bios = Get-WmiObject Win32_bios
    $user = $env:username
    $NetUser = net user
            #$firefox = Write-Output $FirefoxKey.DisplayVersion
    $Firewall = netsh advfirewall show allprofiles
    $Desktop = [Environment]::GetFolderPath("Desktop")
    If ($PSVersionTable.PSVersion.Major -gt 4) {
        $Printer = Get-Printer
        $PrinterDriver = Get-PrinterDriver
    }
    $ProductKey = $SoftwareLicensing.OA3xOriginalProductKey 
        Write-Verbose "Key: $ProductKey" -Verbose

#Storage
    #$Volume = Get-Volume    #Requires Windows 8 or newer. Using "Get-PSDrive" instead.
    $DiskDrives = Get-WMIObject Win32_DiskDrive
    $CDriveModel = ($DiskDrives | Where-Object {$_.deviceID -eq "\\.\PHYSICALDRIVE0"}).Model
    $CDrive = Get-PSDrive -Name C
        $CDriveUsed = $CDrive | ForEach-Object {[math]::Round($_.used / 1GB)}
        $CDriveFree = $CDrive | ForEach-Object {[math]::Round($_.free / 1GB)}
        $CDriveCapacity = $CDrive.Used+$CDrive.Free
            $CDriveCapacity = ForEach-Object {[math]::Round($CDriveCapacity / 1GB)}

        $CDrivePercentUsed = ($CDriveUsed/$CDriveCapacity).ToString("P")
        
        <#Get-Volume -DriveLetter C | select @{L="PercentUsed";E={($_.sizeremaining/$_.size).ToString("P")}}#>
        <#https://blogs.technet.microsoft.com/heyscriptingguy/2014/10/11/weekend-scripter-use-powershell-to-calculate-and-display-percentages/#>

#BitLocker
    $FixedDrives = Get-Volume | Where {$_.DriveType -eq "Fixed"}
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
        

#Video Driver
    $VidDriver = Get-WmiObject win32_VideoController

        $AMDVidDriver = $VidDriver | Where {$_.Name -like "*AMD*" -or $_.Name -like "*Radeon*"}
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
            $NVIDIAVidDriver = $VidDriver | Where {$_.Name -Like "*NVIDIA*"}
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

# #Details Folder
#     $dirDetail = Test-Path "$DestinationFolder\details\$ComputerName"
#         If ($dirDetail -eq "True")
#         {
#             Write-Verbose "Writing to: $DestinationFolder\details\$ComputerName" -Verbose
#         } 
#         Else 
#         {
#             mkdir $DestinationFolder\details\$ComputerName
#         }

#Output
    #Full
            $InventoryFull = [PSCustomObject]@{
                'ID' = $id;
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
                'C BitLocker Volume' = $CBLVolumeStatus;
                'C BitLocker Protection' = $CDBLProtectionStatus;
                'C BitLocker Percentage' = $CBLEncryptionPercentage;
                'D BitLocker Volume' = $DBLVolumeStatus;
                'D BitLocker Protection' = $DDBLProtectionStatus;
                'D BitLocker Percentage' = $DBLEncryptionPercentage;
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
            Write-Output $InventoryFull
            $InventoryFull | Export-Csv -Path $DestinationFolder\InventoryFull.csv -Append                

    <#Library#>     
        If ($DestinationFolder -like "*Library*") 
        {                
            $Library = [PSCustomObject]@{
                'Timestamp' = $date;
                'Hostname' = $ComputerName;
                'Description' = '';
                'User Name' = $user;
                'IP Address' = $FirstIP;
                'Admin Privileges' = $AdminPrivileges;
                'Model Name' = $system.Model;
                'Serial Number' = $bios.SerialNumber;
                'Patch Port' = '';
                'Switchport' = '';
                'Extension/Switch' = '';
                'Location' = '';
                'Type' = '';
                'Password' = '';
        }
            Write-Output $Library
            $Library | Export-Csv -Path $DestinationFolder\Library.csv -Append
        }

    <#IronRidge#>   
        If ($DestinationFolder -like "*IronRidge*") 
        {
            $IronRidge = [PSCustomObject]@{
                'Timestamp' = $date;
                'User Name' = $user;
                'Employees' = $user;
                'Active' = '';
                'Tag' = '';
                'Date Checked' = $DateReadable;
                'Hostname'= $ComputerName;
                'Asset' = 'Laptop';
                'Model Name' = $system.Model;
                'Category' = '';
                'Serial Number' = $bios.SerialNumber;
                'OS' = $os.Caption -replace 'Microsoft ','';
                'Memory' = "$memory GB";
                'Storage' = $CDriveModel;
                'TeamViewer' = $TeamViewer.ClientID;
                'Google Drive' = $GoogleDrive;
                'Special Programs' = ''
                'Location' = ''
                'C Encrypted' = $CBLVolumeStatus;
                'D Encrypted' = $CBLVolumeStatus;
            }
            Write-Output $IronRidge
            $IronRidge | Export-Csv -Path $DestinationFolder\IronRidge.csv -Append
        }

# #Makes text files with detailed information about computer.
#     Write-Output $ipconfig $netAdapter $route $Firewall $date " " >> $DestinationFolder\details\$ComputerName\$Timestamp-detailedNetwork.txt
#     Write-Output $ComputerName $user $system $CPU $bios $NetUser $AdminUsers $VidDriver <#$Printer#> <#$PrinterDriver#> $DiskDrives $date " " >> $DestinationFolder\details\$ComputerName\$Timestamp-detailedSystem.txt
#     Get-WmiObject SoftwareLicensingService >> $DestinationFolder\details\$ComputerName\$Timestamp-detailedSystem.txt
#         if ($os.Version -gt "6.1.7601")
#         {
#             Get-Volume >> $DestinationFolder\details\$ComputerName\$Timestamp-Drives.txt
#             Get-Printer >> $DestinationFolder\details\$ComputerName\$Timestamp-Printers.txt
#         }
#     Write-Output $ComputerName $os $bios $IE $firefox $Chrome $Flash $Java $PSVersionTable $date " " >> $DestinationFolder\details\$ComputerName\$Timestamp-detailedVersion.txt   
# 	    Get-childitem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' | Export-Clixml "$DestinationFolder\details\$ComputerName\$Timestamp-applications.xml"    #lists all installed 32-bit programs in a XML file
# 	    if ($System.SystemType -eq "X64-based PC")    #only for 64-bit computers
#         {
#             Get-childitem 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | Export-Clixml "$DestinationFolder\details\$ComputerName\$Timestamp-applications64.xml"    #lists all installed 64-bit programs in a XML file
#         }

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