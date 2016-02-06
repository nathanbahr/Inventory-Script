#ID
$ipv4add = ipconfig | where-object {$_ -match "IPv4 Address"} | foreach-object{$_.Split(":")[1]}
$ipv6add = ipconfig | where-object {$_ -match "IPv6 Address. . . . . . . . . . . :"} <#| foreach-object{$_.Split(":")[1]}#>

$oct2 = $ipv4add.trim().Split(".")[2]
$oct3 = $ipv4add.trim().Split(".")[3]
$id = "$($oct2)$($oct3)"


#Variables
$hn = hostname
$network = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName 127.0.0.1 -Filter "IpEnabled = TRUE"
$netAdapter = get-wmiobject win32_networkadapter -filter "netconnectionstatus = 2" | select AdapterType | Select -first 1
$ipconfig = ipconfig /all
$route = route print
$system = Get-WmiObject -Class Win32_computerSystem
$memory = Get-WmiObject Win32_computersystem | foreach-object {[math]::round($_.totalPhysicalMemory / 1GB,2)} <#displays the amount of system memory ronded to the hundredths place#>
$bios = Get-WmiObject Win32_bios
$user = $env:username
$date =  Get-Date -format s
$os = Get-WmiObject Win32_operatingSystem
$java = gp  'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\'
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



mkdir Inventory\details\$hn


<#Makes two csv files. 
Inventory.csv: has most system and network information. 
Version.csv: has aplication and OS versions such as Firefox or Windows.
'': represent a blank space to be manual filled in later#>
Write-Output "$($id);$($hn);$($network.DHCPEnabled);$($network.IPAddress<#$ipv4add#>);$($network.IPSubnet);$($network.DefaultIPGateway);$($network.DNSServerSearchOrder);'';$($network.WINSPrimaryServer);$($network.WINSSecondaryServer);$($system.Domain);$($network.MACAddress);$($network.Description);$($netAdapter.AdapterType);'';'';'';'';'';$($user);'';$($system.Manufacturer);$($system.Model);'';'';$($bios.SerialNumber);'';$($memory)GB;$($system.SystemType);$($date)" >> Inventory\Inventory.txt
Write-Output "$($id);$($hn);$($os.Version);$($bios.SMBIOSBIOSVersion);$($bios.Version);$($IE.Version);$(if ($firefox.publisher -eq "Mozilla") {Write-Output $firefox.DisplayVersion} else {Write-Output 'NULL'});$(if ($chrome.displayname -eq "Google Chrome") {Write-Output $chrome.Version} else {Write-Output 'NULL'});$($flash.CurrentVersion);$($java.CurrentVersion);$($java.BrowserJavaVersion);$($date);$($PSVersionTable.PSVersion);'';" >> Inventory\Version.txt

#Makes three text files with detailed information about computer.
Write-Output $ipconfig $netAdapter $route $date " " >> Inventory\details\$hn\detailedNetwork.txt
Write-Output $hn $user $system $bios $date " " >> Inventory\details\$hn\detailedSystem.txt
Write-Output $hn $os $bios $IE $firefox $chrome $flash $java $PSVersionTable $date " " >> Inventory\details\$hn\detailedVersion.txt