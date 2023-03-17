# Enable Local Admin and set Password
Write-Host Passwort für lokaler Administrator eingeben:
$Password = Read-Host -AsSecureString
if(-not ([string]::IsNullOrEmpty($Password))){
    Enable-LocalUser -Name "Administrator"
    Set-LocalUser -Name "Administrator" -PasswordNeverExpires $true
    $UserAccount = Get-LocalUser -Name "Administrator"
    $UserAccount | Set-LocalUser -Password $Password
}

# Change Hostname
Write-Host Hostname eingeben:
$Hostname = Read-Host
if(-not ([string]::IsNullOrEmpty($Hostname))){
    Rename-Computer -NewName $Hostname
}

# Install winget
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe

# Install tools
winget install --force --id "Adobe.Acrobat.Reader.64-bit"
winget install --force --id "Notepad++.Notepad++"
winget install --force --id "Mozilla.Firefox"
winget install --force --id "Google.Chrome"
winget install --force --id "7zip.7zip"
winget install --force --id "PuTTY.PuTTY"

# Install Netextender
winget install --force --id "SonicWALL.NetExtender"

# Uninstall Microsoft Apps
winget uninstall --id "Microsoft.BingWeather_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.GamingApp_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.Getstarted_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.LanguageExperiencePackfr-FR_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.MSPaint_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.Microsoft3DViewer_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.MixedReality.Portal_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.People_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.WindowsMaps_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.Xbox.TCUI_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.XboxApp_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.XboxGameOverlay_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.XboxIdentityProvider_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.XboxIdentityProvider_8wekyb3d8bbwe"
winget uninstall --id "Microsoft.YourPhone_8wekyb3d8bbwe"
winget uninstall --id "SpotifyAB.SpotifyMusic_zpdnekdrzrea0"
winget uninstall --id "O365HomePremRetail - fr-fr"
winget uninstall --id "O365HomePremRetail - en-en"


# Uninstall HP Tools
winget uninstall --id "{C245BEA3-FEDF-4593-A9B0-3DE9C82C09F4}"
winget uninstall --id "{6F14D6F0-7663-11ED-9748-10604B96B11C}"
winget uninstall --id "{5000F75C-32F5-428D-9690-8A522F0C5B76}"
winget uninstall --id "AD2F1837.HPPrivacySettings_v10z8vjag6ke6"
winget uninstall --id "AD2F1837.HPEasyClean_v10z8vjag6ke6"
winget uninstall --id "AD2F1837.HPDesktopSupportUtilities_v10z8vjag6ke6"
winget uninstall --id "AD2F1837.HPQuickDrop_v10z8vjag6ke6"
winget uninstall --id "AD2F1837.HPPCHardwareDiagnosticsWindows_v10z8vjag6ke6"
winget uninstall --id "AD2F1837.myHP_v10z8vjag6ke6"
winget uninstall --id "{C245BEA3-FEDF-4593-A9B0-3DE9C82C09F4}"

# Upgrade all tools
winget upgrade --all -h

# Install Windows Updates
if(-not (Get-InstalledModule -Name "PSWindowsUpdate")){
    Write-Host "PSWindowsUpdate nicht installiert, installieren..."
    Install-Module PSWindowsUpdate
}

Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install

# Check if driveletter of volume C is SYSTEM
if((Get-Volume -driveletter C).FileSystemLabel -ne "SYSTEM"){
    Write-Host "Label C auf SYSTEM umbenennen..."
    Set-Volume -DriveLetter C -NewFileSystemLabel "SYSTEM"
}

# Create temp Directory if not exists 
if(-Not (Test-Path C:\Temp).Exists){
    New-Item "C:\temp" -ItemType Directory
}¨

# Create admin Directory if not exists 
if(-Not (Test-Path C:\admin).Exists){
    New-Item "C:\admin" -ItemType Directory
}

# Set Path Variable TEMP and TMP to C:\temp
[Environment]::SetEnvironmentVariable('TMP', 'C:\Temp', 'User')
[Environment]::SetEnvironmentVariable('TEMP', 'C:\Temp', 'User')

# Install .NET 
Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3"

# Set Power to max. performance
$powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'Höchstleistung'"
$PowerPlanNew = Get-TextWithin $powerPlan.InstanceID -StartChar '{' -EndChar '}'
powercfg.exe -SETACTIVE $PowerPlanNew

# Switch hibernate off
Powercfg /hibernate off

# Set Monitor TimeOut to 0
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-dc 0

# Set Explorer Settings Actual User
$explorerkey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
Set-ItemProperty "$explorerkey" EnableAutoTray 0
Set-ItemProperty "$explorerkey\Advanced" FolderContentsInfoTip 0
Set-ItemProperty "$explorerkey\Advanced" FolderSizeTip 0
Set-ItemProperty "$explorerkey\Advanced" HideFileExt 0
Set-ItemProperty "$explorerkey\Advanced" Hidden 1
Set-ItemProperty "$explorerkey\Advanced" IconsOnly 1
Set-ItemProperty "$explorerkey\Advanced" LaunchTo 1
Set-ItemProperty "$explorerkey\Advanced" SharingWizardOn 0
Set-ItemProperty "$explorerkey\Advanced" ShowInfoTip 0
Set-ItemProperty "$explorerkey\Advanced" ShowTaskViewButton 0
Set-ItemProperty "$explorerkey\Advanced" ShowTypeOverlay 0
Set-ItemProperty "$explorerkey\VisualEffects" VisualFXSetting 2
Set-ItemProperty "$explorerkey\Ribbon" MinimizedStateTabletModeOff 0

$null = New-ItemProperty -Path "$explorerkey\Advanced" -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$explorerkey\Advanced" -Name NavPaneShowAllFolders -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "$explorerkey\Advanced" -Name NavPaneExpandToCurrentFolder -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "$explorerkey\CabinetState" -Name FullPath -PropertyType DWord -Value 1 -Force

$null = New-Item -Path "$explorerkey\ControlPanel"
$null = New-ItemProperty -Path "$explorerkey\ControlPanel" -Name AllItemsIconView -PropertyType DWord -Value 1 -Force

$null = New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$null = New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name ExplorerRibbonStartsMinimized -PropertyType DWord -Value 2 -Force

# Set Explorer SEttings Default User
$null = New-PSDrive HKU Registry HKEY_USERS
$null = reg load HKLM\DefaultUser C:\Users\Default\NTUSER.DAT

# Set CMD QuickEdit
Set-ItemProperty  'HKLM:\Defaultuser\Console' QuickEdit 1

# Set Folder options
$defuserexplorer = "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Explorer"

$null = New-ItemProperty -Path "$defuserexplorer" -Name EnableAutoTray -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name FolderContentsInfoTip -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name FolderSizeTip -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name HideFileExt -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name Hidden -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name IconsOnly -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name LaunchTo -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name SharingWizardOn -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name ShowInfoTip -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name ShowTypeOverlay -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name NavPaneShowAllFolders -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "$defuserexplorer\Advanced" -Name NavPaneExpandToCurrentFolder -PropertyType DWord -Value 1 -Force

$null = New-Item -Path "$defuserexplorer\VisualEffects"
$null = New-ItemProperty -Path "$defuserexplorer\VisualEffects" -Name VisualFXSetting -PropertyType DWord -Value 2 -Force
$null = New-Item -Path "$defuserexplorer\CabinetState"
$null = New-ItemProperty -Path "$defuserexplorer\CabinetState" -Name FullPath -PropertyType DWord -Value 1 -Force
$null = New-Item -Path "$defuserexplorer\ControlPanel"
$null = New-ItemProperty -Path "$defuserexplorer\ControlPanel" -Name AllItemsIconView -PropertyType DWord -Value 1 -Force

Write-Host "Disable Input Indicator..."
$null = New-Item -Path "HKLM:\Defaultuser\Software\Microsoft\CTF\LangBar"
$null = New-ItemProperty -Path "HKLM:\Defaultuser\Software\Microsoft\CTF\LangBar" -Name ShowStatus -PropertyType DWord -Value 3 -Force

Write-Host "System Tray Customizations..."
if ( $win22 -eq $true ) { $null = New-Item "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Search" }
$null = New-ItemProperty -Path "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
$null = New-Item "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Policies"
$null = New-Item "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$null = New-ItemProperty -Path "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HideSCAVolume -PropertyType DWord -Value 1 -Force
$null = New-ItemProperty -Path "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name TaskbarNoNotification -PropertyType DWord -Value 0 -Force

# Unload registry tree
$tmpreg = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Defaultuser\"
$tmpreg.Close()
[gc]::collect()
Start-Sleep -Seconds 2
$null = reg unload HKLM\DefaultUser


# Disable Input Indicator
$null = New-Item -Path "HKCU:\Software\Microsoft\CTF\LangBar"
$null = New-ItemProperty -Path "HKCU:\Software\Microsoft\CTF\LangBar" -Name ShowStatus -PropertyType DWord -Value 3 -Force

# Disable Crash Dumps
$null = bcdedit /timeout 0

# Disable IE Security
$null = New-ItemProperty -Path 'HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -PropertyType DWord -Value 0 -Force

# Set Active Hours
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' ActiveHoursStart 6
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' ActiveHoursEnd 23

# Disable IPv6
Disable-NetAdapterBinding -InterfaceAlias "*" -ComponentID "ms_tcpip6"

# Set TimeServer
$null = w32tm /config /manualpeerlist:"ch.pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update
$null = net stop w32time
$null = net start w32time

# Set default language
Set-WinUserLanguageList de-CH -Force