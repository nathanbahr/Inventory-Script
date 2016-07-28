#Details Folder
    $ComputerName = hostname
    $dirDetail = Test-Path ".\Inventory\details\$ComputerName"
        if ($dirDetail -eq "True") {
            Write-Output "Writing to: Inventory\details\$ComputerName"
        } 
        else {
            mkdir .\Inventory\details\$ComputerName
        }

#ID
    $ipID = ipconfig | Where-Object {$_ -match "IPv4 Address"} | ForEach-Object{$_.Split(":")[1]}

    $oct2 = $ipID.trim().Split(".")[2]
    $oct3 = $ipID.trim().Split(".")[3]
    $id = "$($oct2)$($oct3)"


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
    Write-Output "$($id),$($ComputerName),$($date),$($network.DHCPEnabled | select -First 1),$($FirstIP),$($FirstSub),$($SecondIP),$($SecondSub),$($network.DefaultIPGateway),$($DNS),$($DNSBackup),$($WINS),$($WINSBackup),$($system.Domain),$($network.MACAddress),$($network.Description),$($netAdapter)" >> .\Inventory\Network.csv
    Write-Output "$($id),$($ComputerName),$($date),$($system.Manufacturer),$($system.Model),$($bios.SerialNumber),$($memory)GB,$($system.SystemType),$($user)" >> .\Inventory\System.csv
    Write-Output "$($id),$($ComputerName),$($date),$($os.Version),$($os.BuildNumber),$($bios.SMBIOSBIOSVersion),$($bios.Version),$($bios.Name),$($IE.Version),$($firefoxDV),$($chromeV),$($flashCV),$($javaV),$($PSVersionTable.PSVersion)" >> .\Inventory\Version.csv

#Makes three text files with detailed information about computer.
    Write-Output $ipconfig $netAdapter $route $date " " >> .\Inventory\details\$ComputerName\detailedNetwork.txt
    Write-Output $ComputerName $user $system $bios $date " " >> .\Inventory\details\$ComputerName\detailedSystem.txt
    Write-Output $ComputerName $os $bios $IE $firefox $chrome $flash $java $PSVersionTable $date " " >> .\Inventory\details\$ComputerName\detailedVersion.txt

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
        $ComputerName | Out-File $LogFile -Append
        #$Error | Out-File $LogFile -Append
        $erFlash | Out-File $LogFile -Append
        $erJava | Out-File $LogFile -Append