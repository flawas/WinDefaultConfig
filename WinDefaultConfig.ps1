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
    # Rename-Computer -NewName $Hostname
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
#[Environment]::SetEnvironmentVariable("TEMP", $Env:PATH + ";C:\temp", [EnvironmentVariableTarget]::Machine)
#[Environment]::SetEnvironmentVariable("TMP", $Env:PATH + ";C:\temp", [EnvironmentVariableTarget]::Machine)

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