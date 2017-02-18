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
        $Java = Get-ItemProperty $JavaKey | where {$_.DisplayName -like 'Java *'}    #Get the properties of the correct registry key
        Write-Verbose "Java Runtime Environment (JRE): $($Java.DisplayVersion)" -Verbose    #Display the version of JRE to the console
    }
    Else
    {
        $Java = Write-Output 'NULL'
        Write-Verbose "Java Runtime Environment (JRE): NULL or incorect '*bit' version installed" -Verbose
    }

        $NewestJavaFile = Get-ItemProperty .\NewestJava.txt
        $JavaFileDifference = $NewestFlashFile.LastWriteTime-$DateRegular
        If ($javahFileDiffernce.Hour -gt 24 -and $PSVersionTable.PSVersion.Major -gt 2)
        {
            #Is Java updated?

$javacom = Invoke-WebRequest "http://www.java.com/en/download/"
            $NewestJava = $javacom.AllElements | Where-Object {$_.InnerHtml -like "Version * Update *"} | Select-Object innerHTML -First 1
                Write-Output $NewestJava.innerHTML > .\NewestJava.txt
                
                (Get-Content .\NewestJava.txt) -replace 'Version','Java' | Foreach {$_.TrimEnd()} | Set-Content .\NewestJava.txt    #Replaces the word 'Version' that is pulled from the web page to 'Java' to match what is in WMI.
        }
        Else
        {
            Write-Verbose "Reading plug-in version from file..." -Verbose
        }


      #removes 64-bit from the Java name so just the version is compared.
        $JavaName = $Java.DisplayName -replace "\(64-bit\)","" | Foreach {$_.TrimEnd()}
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
    IF ($system.SystemType -eq "X86-based PC") 
    {
        $FirefoxKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
    }
    Else 
    {
        $FirefoxKey = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
    }

    $FirefoxTest = Test-Path $FirefoxKey
    $Firefox = If ($FirefoxTest -eq "True") 
        {
            Get-ItemProperty $FirefoxKey
        } 
        else 
        {
            Write-Output 'NULL'
        }

            $FirefoxVersion = if ([string]::IsNullOrEmpty($Firefox.DisplayVersion)) 
                {
                    Write-Output 'NULL'
                } 
                else 
                {
                    Write-Output $Firefox.DisplayVersion | Foreach {$_.TrimEnd()}
                }

                If ($FirefoxVersion -NotLike "51.0.1") 
                {
                    $FirefoxPath = $firefox.DisplayIcon -replace ",0",""    #Sets the path to Firefox from the registry.
                    Start-Process $FirefoxPath     #Opens Firefox to manually run the built-in auto update.
                }
                Else 
                {
                    #Outputs the version of Firefox that is currently installed. (Usfull for troubleshooting in case the script grabbed the wrong version number.)
                        Write-Verbose "Firefox:  $FirefoxVersion" -Verbose
                }

#Internet Explorer
    $IE = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'

	
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




#NULL
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


#Errors
    $LogFile = '.\Inventory\details\log.txt'
        Get-Date | Out-File $LogFile -Append
        $hn | Out-File $LogFile -Append
        #$Error | Out-File $LogFile -Append
        $erFlash | Out-File $LogFile -Append
        $erJava | Out-File $LogFile -Append
