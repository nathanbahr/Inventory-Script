#Details Folder
$hn = hostname
$dirDetail = Test-Path ".\Inventory\details\$hn"
if ($dirDetail -eq "True") {Write-Output "Writing to: Inventory\details\$hn"} else {mkdir .\Inventory\details\$hn}

#ID
$ipv4add = ipconfig | where-object {$_ -match "IPv4 Address"} | foreach-object{$_.Split(":")[1]}
$ipv6add = ipconfig | where-object {$_ -match "IPv6 Address. . . . . . . . . . . :"} <#| foreach-object{$_.Split(":")[1]}#>

$oct2 = $ipv4add.trim().Split(".")[2]
$oct3 = $ipv4add.trim().Split(".")[3]
$id = "$($oct2)$($oct3)"


#Variables
$network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
if ($network.Description -like "*Wireless*") {
        $netAdapter = "Wireless"
    } else {
        $netAdapter = Get-WmiObject win32_networkadapter -filter "netconnectionstatus = 2" | select AdapterType | Select -first 1
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
$flash =  gp  'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
$IE = gp 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'

#32 bit applications
IF ($system.SystemType -eq "X86-based PC") {
    $firefox = gp  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
	$chrome = gp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
}
Else {
    $firefox = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
	$chrome = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome\'
}

#NULL
$firefoxDV = if ($firefox.publisher -eq "Mozilla") {Write-Output $firefox.DisplayVersion} else {Write-Output 'NULL'}
$chromeV = if ($chrome.displayname -eq "Google Chrome") {Write-Output $chrome.Version} else {Write-Output 'NULL'}
$flashCV = if ($flash.PSChildName -eq "FlashPlayer") {Write-Output $flash.CurrentVersion} else {Write-Output 'NULL'}
$javaV = if ($java.Vendor -eq "Oracle Corporation") {Write-Output $java | Select -Expand Version -Last 1} else {Write-Output 'NULL'}
$WINS = if ([string]::IsNullOrEmpty($network.WINSPrimaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSPrimaryServer}
$WINSBackup = if ([string]::IsNullOrEmpty($network.WINSSecondaryServer)) {Write-Output 'NULL'} else {Write-Output $network.WINSSecondaryServer}



<#Makes two txt files. 
Inventory.txt: has most system and network information. 
Version.txt: has application and OS versions such as Firefox or Windows.
'': represents a blank space to be manually filled in later#>
Write-Output "$($id);$($hn);$($network.DHCPEnabled);$($network.IPAddress<#$ipv4add#>);$($network.IPSubnet);$($network.DefaultIPGateway);$($network.DNSServerSearchOrder[0]);$($network.DNSServerSearchOrder[1]);$($WINS);$($WINSBackup);$($system.Domain);$($network.MACAddress);$($network.Description);$($netAdapter);'';'';'';'';'';$($user);'';$($system.Manufacturer);$($system.Model);'';'';$($bios.SerialNumber);'';$($memory)GB;$($system.SystemType);$($date);" >> Inventory\Inventory.txt
Write-Output "$($id);$($hn);$($os.Version);$($os.BuildNumber);$($bios.SMBIOSBIOSVersion);$($bios.Version);$($bios.Name);$($IE.Version);$($firefoxDV);$($chromeV);$($flashCV);$($javaV);$($PSVersionTable.PSVersion);$($date);" >> Inventory\Version.txt

#Makes three text files with detailed information about computer.
Write-Output $ipconfig $netAdapter $route $date " " >> Inventory\details\$hn\detailedNetwork.txt
Write-Output $hn $user $system $bios $date " " >> Inventory\details\$hn\detailedSystem.txt
Write-Output $hn $os $bios $IE $firefox $chrome $flash $java $PSVersionTable $date " " >> Inventory\details\$hn\detailedVersion.txt