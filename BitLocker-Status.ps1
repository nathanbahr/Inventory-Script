#BitLocker

#MSUT RUN AS ADMINISTRATOR

$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$BIOS = Get-CimInstance Win32_BIOS
$BitLockerVolume = Get-BitLockerVolume -MountPoint C:


$DestinationTXT = Test-Path .\dest.txt
If ($DestinationTXT -eq $false) {
    $DestinationFolder = ".\Computers"
}
else {
    $DestinationFolder = Get-Content .\dest.txt
}


$DestinationFolderPath = Test-Path $DestinationFolder
If ($DestinationFolderPath -eq 'True') {
    Write-Verbose "Using existing folder: $($DestinationFolder)" -Verbose
} 
Else {
    mkdir "$($DestinationFolder)"
}


$PowerShellAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")     #check if PowerShell is running as an administrator
#https://superuser.com/questions/749243/detect-if-powershell-is-running-as-administrator

if ($PowerShellAdmin -eq $true) {
    $BitLocker = [PSCustomObject]@{
        'MountPoint'           = $BitLockerVolume.MountPoint;
        'EncryptionMethod'     = $BitLockerVolume.EncryptionMethod;
        'AutoUnlockEnabled'    = $BitLockerVolume.AutoUnlockEnabled;
        'AutoUnlockKeyStored'  = $BitLockerVolume.AutoUnlockKeyStored;
        'MetadataVersion'      = $BitLockerVolume.MetadataVersion;
        'VolumeStatus'         = $BitLockerVolume.VolumeStatus;
        'ProtectionStatus'     = $BitLockerVolume.ProtectionStatus;
        'LockStatus'           = $BitLockerVolume.LockStatus;
        'EncryptionPercentage' = $BitLockerVolume.EncryptionPercentage;
        'WipePercentage'       = $BitLockerVolume.WipePercentage;
        'VolumeType'           = $BitLockerVolume.VolumeType;
        'CapacityGB'           = $BitLockerVolume.CapacityGB;
        'ComputerName'         = $BitLockerVolume.ComputerName;
        'SerialNumber'         = $BIOS.SerialNumber;
        'Timestamp'            = $Timestamp;
    }
    $BitLocker | Export-Csv -Path $DestinationFolder\BitLocker.csv -Append -NoTypeInformation
}
else {
    Write-Error "Must run as administrator to check BitLocker status"
}
Write-Output $BitLocker