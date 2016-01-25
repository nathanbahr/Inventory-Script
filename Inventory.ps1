#ID
$oct2 = ipconfig | where-object {$_ -match "IPv4 Address"} | foreach-object{$_.Split(":")[1].trim().Split(".")[2]}
$oct3 = ipconfig | where-object {$_ -match "IPv4 Address"} | foreach-object{$_.Split(":")[1].trim().Split(".")[3]}
$id = "$($oct2)$($oct3)"


#Variables
$hn = hostname
$network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
#$netAdapter = Get-WmiObject -Class "Win32_NetworkAdapter" | select AdapterType
$ipconfig = ipconfig /all
$route = route print
$system = Get-WmiObject -Class Win32_computerSystem
$memory = Get-WmiObject Win32_computersystem | foreach-object {[math]::round($_.totalPhysicalMemory / 1GB,2)}
$bios = Get-WmiObject Win32_bios
$user = $env:username
$date =  Get-Date -format s
$os = Get-WmiObject Win32_operatingSystem
$java = gp  'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\'
$flash =  gp  'HKLM:\SOFTWARE\Macromedia\FlashPlayer\'
#$firefox = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*' 
#$firefox32 = gp  'HKCU:\SOFTWARE\Mozilla\Mozilla Firefox\' 
$chrome = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome\' <#| foreach { if ($chrome = $null) {Write-Output NULL} else {Write-Output $chrome.Version} }#>
#$chrome32 = gp 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
$IE = gp 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'

#firefox
IF ($system.SystemType -eq "X86-based PC") {
    $firefox = gp  'HKLM:\SOFTWARE\Mozilla\Firefox\Mozilla Firefox*'
}
Else {
    $firefox = gp 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*'
}


mkdir Inventory\details\$hn


<#Makes two csv files. 
Inventory.csv: has most system and network information. 
Version.csv: has aplication and OS versions such as Firefox or Windows.
'': represent a blank space to be manual filled in later#>
Write-Output "$($id);$($hn);$($network.DHCPEnabled);$($network.IPAddress);$($network.IPSubnet);$($network.DefaultIPGateway);$($network.DNSServerSearchOrder);'';$($network.WINSPrimaryServer);$($network.WINSSecondaryServer);$($system.Domain);$($network.MACAddress);$($network.Description);'';'';'';'';'';'';$($user);'';$($system.Manufacturer);$($system.Model);'';'';$($bios.SerialNumber);'';$($memory)GB;$($system.SystemType);$($date)" >> Inventory\Inventory.txt
Write-Output "$($id);$($hn);$($os.Version);$($bios.SMBIOSBIOSVersion);$($bios.Version);$($IE.Version);$($firefox.DisplayVersion);$($chrome.Version);$($flash.CurrentVersion);$($java.CurrentVersion);$($java.BrowserJavaVersion);$($date);'';" >> Inventory\Version.txt

#Makes three text files with detailed information about computer.
Write-Output $ipconfig $route $date " " >> Inventory\details\$hn\detailedNetwork.txt
Write-Output $hn $user $system $bios $date " " >> Inventory\details\$hn\detailedSystem.txt
Write-Output $hn $os $bios $IE $firefox $chrome $flash $java $date " " >> Inventory\details\$hn\detailedVersion.txt

#Copy-Item -Recurse $env:USERPROFILE\AppData\Roaming\TeamViewer Inventory\details\$hn