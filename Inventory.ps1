$hn = hostname
$network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
#$netAdapter = Get-WmiObject -Class "Win32_NetworkAdapter" | select AdapterType
$ipconfig = ipconfig /all
$route = route print
$system = Get-WmiObject -Class Win32_computerSystem
$bios = Get-WmiObject Win32_bios
$user = $env:username
$date =  Get-Date -format s
$os = Get-WmiObject Win32_operatingSystem
$java = gp  'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\'
$flash =  gp  'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
$firefox = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*' 
#$firefox32 = gp  'HKCU:\SOFTWARE\Mozilla\Mozilla Firefox\' 
$chrome = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome\' <#| foreach { if ($chrome = $null) {Write-Output NULL} else {Write-Output $chrome.Version} }#>
#$chrome32 = gp 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
$IE = gp 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'



mkdir Inventory\details\$hn


<#Makes two csv files. 
Inventory.csv: has most system and network information. 
Version.csv: has aplication and OS versions such as Firefox or Windows.
'': represent a blank space to be manual filled in later#>
Write-Output "$($hn),$($network.DHCPEnabled),$($network.IPAddress),'',$($network.DefaultIPGateway),$($network.DNSServerSearchOrder),'',$($network.WINSPrimaryServer),$($network.WINSSecondaryServer),$($system.Domain),$($network.MACAddress),$($network.Description),'','','','','','',$($user),'',$($system.Manufacturer),$($system.Model),'','',$($bios.SerialNumber),'',$($system.TotalPhysicalMemory),$($system.SystemType $date)" >> Inventory\Inventory.csv
Write-Output "$($hn),$($os.Version),$($bios.SMBIOSBIOSVersion),$($bios.Version),$($IE.Version),$($firefox.DisplayVersion),$($chrome.Version),$($flash.CurrentVersion),$($java.CurrentVersion),$($java.BrowserJavaVersion),$($date),''," >> Inventory\Version.csv

#Makes three text files with detailed information about computer.
Write-Output $ipconfig $route $date " " >> Inventory\details\$hn\detailedNetwork.txt
Write-Output $hn $user $system $bios $date " " >> Inventory\details\$hn\detailedSystem.txt
Write-Output $hn $os $bios $IE $firefox $chrome $flash $java $date " " >> Inventory\details\$hn\detailedVer.txt

#Copy-Item -Recurse $env:USERPROFILE\AppData\Roaming\TeamViewer Inventory\details\$hn