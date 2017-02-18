    $System = Get-WmiObject Win32_ComputerSystem
    $SoftwareLicensing = Get-WmiObject SoftwareLicensingService


#Date
    $Date =  Get-Date -format s
    $DateRegular = Get-Date
    $DateReadable = Get-Date -Format g
    $Timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}

#Destination Folder
    $DestinationFolder = '.\Library\Inventory'
    $DestinationFolderPath = Test-Path $DestinationFolder
        If ($DestinationFolderPath -eq 'True') 
        {
            Write-Verbose "Using existing folder: $($DestinationFolder)" -Verbose
        } 
        Else 
        {
            mkdir "$($DestinationFolder)"
        }

#Details Folder
    $ComputerName = hostname
    $dirDetail = Test-Path "$DestinationFolder\details\$ComputerName"
        If ($dirDetail -eq "True") 
        {
            Write-Verbose "Writing to: $DestinationFolder\details\$ComputerName" -Verbose
        } 
        Else 
        {
            mkdir $DestinationFolder\details\$ComputerName
        }

#ID
    $ipID = ipconfig | Where-Object {$_ -match "IPv4 Address"} | ForEach-Object{$_.Split(":")[1]}
    $oct0 = $ipID.trim().Split(".")[0]
    $oct1 = $ipID.trim().Split(".")[1]
    $oct2 = $ipID.trim().Split(".")[2]
    $oct3 = $ipID.trim().Split(".")[3]
    $id = "$($oct2)$($oct3)"


#Flash
    $Flash =  Get-ItemProperty 'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
    $Flash = if ([string]::IsNullOrEmpty($Flash.CurrentVersion))
             {
                 Write-Output 'NULL'
             }
             else 
             {
                 Write-Output $Flash.CurrentVersion | foreach {$_ -replace ",", "."}     #Replaces commas “,” with periods “.” for consistency.
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
    $NewestFlashFile = Get-ItemProperty .\NewestFlash.txt    #Find the date the file was last modified
    $FlashFileDiffernce = $NewestFlashFile.LastWriteTime-$DateRegular    #Subtract the file date from the current date/time.
    If ($FlashFileDiffernce.Hour -gt 24 -and $PSVersionTable.PSVersion.Major -gt 2)    #Invoke-WebRequest requires PowerShell version 3+.
    {
        #Is Flash updated? 
        $adobecom = Invoke-WebRequest "https://get.adobe.com/flashplayer/"                                                         #Check Adobe's website for the latest version number.
        $NewestFlash = $adobecom.AllElements | Where-Object {$_.InnerHtml -like "version *"} | Select-Object innerHTML -First 1    #Select the version number from the webpage.
            Write-Output $NewestFlash.innerHTML > .\NewestFlash.txt                                                                #Write it to a file.
            (Get-Content .\NewestFlash.txt) -replace 'Version ','' | Foreach {$_.TrimEnd()} | Set-Content .\NewestFlash.txt        #Cleanup the output and make it ready to be read.
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
			                $FlashInstallers = Get-ChildItem ".\flash\flashplayer*install.exe"	
                            foreach ($Installer in $FlashInstallers) 
                            {
                                Copy-Item $Installer $env:TEMP
                                Start-Process $Installer -Wait
                            }
                            #clean up
                            Remove-Item "$env:TEMP\flashplayer*install.exe"
                               
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


#Variables
    $network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
    if ($network.Description -like "*Wireless*") {
            $netAdapter = "Wireless"
        } else {
            $AdapterType = Get-WmiObject win32_networkadapter -filter "netconnectionstatus = 2" | select AdapterType | Select -first 1
            $netAdapter =  $AdapterType.AdapterType
        }
    $ipconfig = ipconfig /all
    $route = route print
    $system = Get-WmiObject -Class Win32_computerSystem
    $memory = Get-WmiObject Win32_computersystem | foreach-object {[math]::round($_.totalPhysicalMemory / 1GB,2)} <#displays the amount of system memory rounded to the hundredths place#>
    $bios = Get-WmiObject Win32_bios
    $user = $env:username
    $date =  Get-Date -format s
    $os = Get-WmiObject Win32_operatingSystem
    $java = Get-WmiObject -Class Win32_Product -Filter "Name like 'Java % Update %'" | Sort-Object Version
    $flash =  Get-ItemProperty 'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
    $IE = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'

#32 bit applications
    IF ($system.SystemType -eq "X86-based PC") {
        $firefox = Get-ItemProperty  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
	    $chrome = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
    }
    Else {
        $firefox = Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
	    $chrome = Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome\'
    }

#NULL
    $firefoxDV = if ([string]::IsNullOrEmpty($firefox.DisplayVersion)) {Write-Output 'NULL'} else {Write-Output $firefox.DisplayVersion}
    $chromeV = if ([string]::IsNullOrEmpty($chrome.Version)) {Write-Output 'NULL'} else {Write-Output $chrome.Version}
    $flashCV = if ([string]::IsNullOrEmpty($flash.CurrentVersion)) {Write-Output 'NULL'} else {Write-Output $flash.CurrentVersion}
          $flashCV = $flashCV.Replace(",",".")
    $javaV = if ([string]::IsNullOrEmpty($java)) {Write-Output 'NULL'} else {Write-Output $java | Select -Expand Version -Last 1}
    $FirstIP = if ([string]::IsNullOrEmpty($network.IPAddress[0])) {Write-Output 'NULL'} else {Write-Output $network.IPAddress[0]}
    $SecondIP = if ([string]::IsNullOrEmpty($network.IPAddress[1])) {Write-Output 'NULL'} else {Write-Output $network.IPAddress[1]}
    $FirstSub = if ([string]::IsNullOrEmpty($network.IPSubnet[0])) {Write-Output 'NULL'} else {Write-Output $network.IPSubnet[0]}
    $SecondSub = if ([string]::IsNullOrEmpty($network.IPSubnet[1])) {Write-Output 'NULL'} else {Write-Output $network.IPSubnet[1]}
    $WINS = if ([string]::IsNullOrEmpty($network.WINSPrimaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSPrimaryServer}
    $WINSBackup = if ([string]::IsNullOrEmpty($network.WINSSecondaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSSecondaryServer}
    $DNS = if ([string]::IsNullOrEmpty($network.DNSServerSearchOrder[0])) {Write-Output 'NULL'} else {Write-Output $network.DNSServerSearchOrder[0]}
    $DNSBackup = if ([string]::IsNullOrEmpty($network.DNSServerSearchOrder[1])) {Write-Output 'NULL'} else {Write-Output $network.DNSServerSearchOrder[1..4]}

<#Makes two txt files. 
Inventory.csv: has most system and network information. 
Version.csv: has application and OS versions such as Firefox or Windows.
'': represents a blank space to be manually filled in later#>
    Write-Output "$($id),$($hn),$($date),$($network.DHCPEnabled | select -First 1),$($FirstIP),$($FirstSub),$($SecondIP),$($SecondSub),$($network.DefaultIPGateway),$($DNS),$($DNSBackup),$($WINS),$($WINSBackup),$($system.Domain),$($network.MACAddress),$($network.Description),$($netAdapter)" >> .\Inventory\Network.csv
    Write-Output "$($id),$($hn),$($date),$($system.Manufacturer),$($system.Model),$($bios.SerialNumber),$($memory)GB,$($system.SystemType),$($user)" >> .\Inventory\System.csv
    Write-Output "$($id),$($hn),$($date),$($os.Version),$($os.BuildNumber),$($bios.SMBIOSBIOSVersion),$($bios.Version),$($bios.Name),$($IE.Version),$($firefoxDV),$($chromeV),$($flashCV),$($javaV),$($PSVersionTable.PSVersion)" >> .\Inventory\Version.csv

#Makes three text files with detailed information about computer.
    Write-Output $ipconfig $netAdapter $route $date " " >> .\Inventory\details\$hn\detailedNetwork.txt
    Write-Output $hn $user $system $bios $date " " >> .\Inventory\details\$hn\detailedSystem.txt
    Write-Output $hn $os $bios $IE $firefox $chrome $flash $java $PSVersionTable $date " " >> .\Inventory\details\$hn\detailedVersion.txt

#run for PowerShell version 2:

#Is Flash updated?
    $adobecom = Invoke-WebRequest "https://get.adobe.com/flashplayer/"
    $NewestFlash = $adobecom.AllElements | Where-Object {$_.InnerHtml -like "version *"} | Select-Object innerHTML -First 1
    Write-Output $NewestFlash > .\inventory\NewestFlash.txt
    $NewestFlash = Get-Content .\Inventory\NewestFlash.txt
    if ($flash.CurrentVersion -ne $NewestFlash) {Write-Error -ErrorVariable erFlash -Message "Flash needs to be updated"} else {Write-Output "Flash is up-to-date"}

#Is Java updated?
    $javacom = Invoke-WebRequest "http://www.java.com/en/download/"
    $NewestJava = $javacom.AllElements | Where-Object {$_.InnerHtml -like "Version * Update *"} | Select-Object innerHTML -First 1
    Write-Output $NewestJava > .\inventory\NewestJava.txt
    $NewestJava = Get-Content .\Inventory\NewestJava.txt
    if ($javaV.Name -ne $NewestJava) {Write-Error -ErrorVariable erJava -Message "Java needs to be updated"} else {Write-Output "Java is up-to-date"}


#Errors
    $LogFile = '.\Inventory\details\log.txt'
        Get-Date | Out-File $LogFile -Append
        $hn | Out-File $LogFile -Append
        #$Error | Out-File $LogFile -Append
        $erFlash | Out-File $LogFile -Append
        $erJava | Out-File $LogFile -Append
