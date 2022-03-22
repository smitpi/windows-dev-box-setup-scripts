# Description: Boxstarter Script
# Author: Microsoft
# Common dev settings for machine learning using only Windows native tools

Disable-UAC

<#
# Get the base URI path from the ScriptToCall value
$bstrappackage = "-bootstrapPackage"
$helperUri = $Boxstarter['ScriptToCall']
$strpos = $helperUri.IndexOf($bstrappackage)
$helperUri = $helperUri.Substring($strpos + $bstrappackage.Length)
$helperUri = $helperUri.TrimStart("'", " ")
$helperUri = $helperUri.TrimEnd("'", " ")
$helperUri = $helperUri.Substring(0, $helperUri.LastIndexOf("/"))
$helperUri += "/scripts"
write-host "helper script base URI is $helperUri"

function executeScript {
    Param ([string]$script)
    write-host "executing $helperUri/$script ..."
	iex ((new-object net.webclient).DownloadString("$helperUri/$script"))
}
#>
function Set-LabSettingsOnly {
    #region Lab settings
    #region bginfo
    $checkver = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object caption
    if ($checkver -like '*server*') {
        try {
            Write-Host '[Importing]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'BGInfo' -ForegroundColor Cyan
            Install-BGInfo -RunBGInfo 
        } catch {Write-Warning "Error: `nMessage:$($_.Exception.Message)`nItem:$($_.Exception.ItemName)"}
    }
    #endregion

    #region ssh
    Write-Host '[Importing]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'SSH Config' -ForegroundColor Cyan
    Write-Host 'SSH' -ForegroundColor red
    $Exe = 'robocopy'
    $Param = @("\\dfnas\profile\Utils\LabScripts\Private\App_Setup\ssh $env:USERPROFILE\.ssh /W:0 /R:0 /W:0 /R:0 /NJH /NJS")
    $ParamS = $Param.Split(' ')
    & "$Exe" $ParamS
    #endregion

    #region Windows terminal
    if (Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe") {
        try {
            Write-Host '[Importing]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'Windows Terminal Preview Config' -ForegroundColor Cyan
            Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json" -ErrorAction SilentlyContinue
            $Exe = 'robocopy'
            $Param = @("\\dfnas\profile\Utils\LabScripts\Private\App_Setup\WindowsTerminal $env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState /IF *.json /mir /NJH /NJS")
            $ParamS = $Param.Split(' ')
            & "$Exe" $ParamS
        } catch { Write-Warning 'Does not exist' }
    }

    if (Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe") {
        try {
            Write-Host '[Importing]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'Windows Terminal Config' -ForegroundColor Cyan
            Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" -ErrorAction SilentlyContinue
            $Exe = 'robocopy'
            $Param = @("\\dfnas\profile\Utils\LabScripts\Private\App_Setup\WindowsTerminal $env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState /IF *.json /mir /NJH /NJS")
            $ParamS = $Param.Split(' ')
            & "$Exe" $ParamS
        } catch { Write-Warning 'Does not exist' }
    }
    #endregion

    #region pslauncher
    Write-Host '[Installing]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'PSLauncher' -ForegroundColor Cyan
    $ps5Folder = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), 'WindowsPowerShell', 'Scripts')
    if (-not(Test-Path $ps5Folder)) {
        $psfolder = New-Item -Path $ps5Folder -ItemType Directory -Force
    } else {$psfolder = Get-Item $ps5Folder}


    Remove-Item (Join-Path -Path $psfolder.FullName -ChildPath '\PSLauncher.ps1') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path -Path $psfolder.FullName -ChildPath '\PSSysTrayLauncher.ps1') -Force -ErrorAction SilentlyContinue

    $PSLauncher = New-Item -Path (Join-Path -Path $psfolder.FullName -ChildPath '\PSLauncher.ps1') -ItemType File -Value 'Start-PSLauncher -ConfigFilePath \\dfnas\profile\Utils\LabScripts\Private\App_Setup\PSLauncher\PSLauncherConfig.json'
    $PSSysTrayLauncher = New-Item -Path (Join-Path -Path $psfolder.FullName -ChildPath '\PSSysTrayLauncher.ps1') -ItemType File -Value 'Start-PSSysTrayLauncher -ConfigFilePath \\dfnas\profile\Utils\LabScripts\Private\App_Setup\PSLauncher\PSLauncherConfig.json'
    $PS_SysTray = New-Item -Path (Join-Path -Path $psfolder.FullName -ChildPath '\PS_SysTray.ps1') -ItemType File -Value 'Start-PS_CSV_SysTray -ConfigFilePath \\dfnas\Profile\Utils\LabScripts\Private\App_Setup\PSLauncher\PS_CSV_SysTrayConfig.csv'
    #endregion

    #region delete icons
    Write-Host '[Deleting]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'Old icons' -ForegroundColor Cyan
    $LFolder = [IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'Lab Tools')
    Remove-Item "$ps5Folder\*.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$([Environment]::GetFolderPath('Desktop'))\*.lnk" -ErrorAction SilentlyContinue
    Remove-Item $LFolder -Recurse -Force -ErrorAction SilentlyContinue
    #endregion

    #region ElevatedShortcut
    Write-Host '[Installing]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'ElevatedShortcuts' -ForegroundColor Cyan
    if (Get-ScheduledTask -TaskPath '\RunAs\' -ErrorAction SilentlyContinue) {Get-ScheduledTask -TaskPath '\RunAs\' | Unregister-ScheduledTask -Confirm:$false}
    New-ElevatedShortcut -ShortcutName PSLauncher -FilePath $PSLauncher.FullName | Out-Null
    New-ElevatedShortcut -ShortcutName PS_SysTray -FilePath $PS_SysTray.FullName | Out-Null
    New-ElevatedShortcut -ShortcutName PSSysTrayLauncher -FilePath $PSSysTrayLauncher.FullName | Out-Null
    if (Get-Command wt.exe -ErrorAction SilentlyContinue) {New-ElevatedShortcut -ShortcutName Terminal -FilePath 'C:\Users\ps\AppData\Local\Microsoft\WindowsApps\wt.exe' | Out-Null}
    New-ElevatedShortcut -ShortcutName 'CommandPrompt' -FilePath 'C:\Windows\System32\cmd.exe' | Out-Null
    New-ElevatedShortcut -ShortcutName 'PSISE' -FilePath 'C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe' | Out-Null
    New-ElevatedShortcut -ShortcutName 'WindowsPowershell' -FilePath 'C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe' | Out-Null
    if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) {New-ElevatedShortcut -ShortcutName 'Powershell' -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' | Out-Null}
    if (Test-Path 'C:\Program Files\Microsoft VS Code\Code.exe') {New-ElevatedShortcut -ShortcutName 'VSCode' -FilePath 'C:\Program Files\Microsoft VS Code\Code.exe' | Out-Null}
    #endregion

    #region Shortcuts
    Write-Host '[Creating]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'Shortcuts folder' -ForegroundColor Cyan

    $Labtools = New-Item $LFolder -ItemType Directory -Force 

    if (-not(Test-Path "$env:ProgramFiles\PSToolKit\icons")) {New-Item -Path "$env:ProgramFiles\PSToolKit\icons" -ItemType Directory | Out-Null}
    Copy-Item -Path '\\dfnas\Profile\Utils\LabScripts\Private\ico\pool\*.ico' -Destination "$env:ProgramFiles\PSToolKit\icons" -Force

    #Copy-Item (Join-Path -Path $psfolder.FullName -ChildPath '\PSSysTrayLauncher.lnk') -Destination "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force


    #Copy-Item "$ps5Folder\*.lnk" -Destination $Labtools.FullName -Force
    Move-Item 'C:\Windows\System32\CommandPrompt.lnk' -Destination $Labtools.FullName -Force
    Move-Item 'C:\Program Files\PowerShell\7\Powershell.lnk' -Destination $Labtools.FullName -Force
    Move-Item 'C:\Windows\System32\WindowsPowerShell\v1.0\PSISE.lnk' -Destination $Labtools.FullName -Force
    Move-Item 'C:\Windows\System32\WindowsPowerShell\v1.0\WindowsPowershell.lnk' -Destination $Labtools.FullName -Force
    if (Test-Path 'C:\Program Files\Microsoft VS Code\Code.exe') {Move-Item 'C:\Program Files\Microsoft VS Code\VSCode.lnk' -Destination $Labtools.FullName -Force}

    # $WScriptShell = New-Object -ComObject WScript.Shell
    # $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\StartUp Folder.lnk'))
    # $Shortcut.TargetPath = 'explorer.exe'
    # $Shortcut.Arguments = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    # $Shortcut.Save()

    # $WScriptShell = New-Object -ComObject WScript.Shell
    # $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\App Setup Folder.lnk'))
    # $Shortcut.TargetPath = 'explorer.exe'
    # $Shortcut.Arguments = '\\dfnas\Profile\Utils\LabScripts\Private\App_Setup'
    # $Shortcut.Save()

    # $WScriptShell = New-Object -ComObject WScript.Shell
    # $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\AdminTools.lnk'))
    # $Shortcut.TargetPath = 'explorer.exe'
    # $Shortcut.Arguments = '\\vulcan.internal.lab\SharedProfile\CloudStorage\Dropbox\#Profile\AdminTools'
    # $Shortcut.Save()

    # $WScriptShell = New-Object -ComObject WScript.Shell
    # $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\Downloads.lnk'))
    # $Shortcut.TargetPath = 'explorer.exe'
    # $Shortcut.Arguments = '\\vulcan.internal.lab\SharedProfile\Download'
    # $Shortcut.Save()

    # $WScriptShell = New-Object -ComObject WScript.Shell
    # $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\AllUsers Modules.lnk'))
    # $Shortcut.TargetPath = 'explorer.exe'
    # $Shortcut.Arguments = 'C:\Program Files\WindowsPowerShell\Modules'
    # $Shortcut.Save()

    if (Get-Command wt.exe -ErrorAction SilentlyContinue) {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\Terminal.lnk'))
        $Shortcut.TargetPath = 'C:\Windows\System32\schtasks.exe'
        $Shortcut.Arguments = '/run /tn RunAs\Terminal'
        $Shortcut.IconLocation = "$env:ProgramFiles\PSToolKit\icons\pool-8.ico"
        $Shortcut.Save()
    }

    if (Test-Path 'C:\Program Files\PSToolKit\BGInfo') {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\BGInfo.lnk'))
        $Shortcut.TargetPath = 'C:\Program Files\PSToolKit\BGInfo\Bginfo64.exe' 
        $Shortcut.Arguments = '"C:\Program Files\PSToolKit\BGInfo\PSToolKit.bgi" /timer:0 /nolicprompt'
        $Shortcut.IconLocation = 'C:\Program Files\PSToolKit\icons\pool-13.ico'
        $Shortcut.Save()
    }

        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\PSSysTrayLauncher.lnk'))
        $Shortcut.TargetPath = 'C:\Windows\System32\schtasks.exe' 
        $Shortcut.Arguments = '/run /tn RunAs\PSSysTrayLauncher'
        $Shortcut.IconLocation = 'C:\Program Files\PSToolKit\icons\pool-2.ico'
        $Shortcut.Save()
   
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\PSLauncher.lnk'))
        $Shortcut.TargetPath =  'C:\Windows\System32\schtasks.exe' 
        $Shortcut.Arguments = '/run /tn RunAs\PSLauncher'
        $Shortcut.IconLocation = 'C:\Program Files\PSToolKit\icons\pool-3.ico'
        $Shortcut.Save()
    
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut((Join-Path -Path $Labtools.FullName -ChildPath '\PS_SysTray.lnk'))
        $Shortcut.TargetPath = 'C:\Windows\System32\schtasks.exe'  
        $Shortcut.Arguments = '/run /tn RunAs\PS_SysTray'
        $Shortcut.IconLocation = 'C:\Program Files\PSToolKit\icons\pool-4.ico'
        $Shortcut.Save()
    
    If ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').Property -contains 'PSSysTrayLauncher') {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PSSysTrayLauncher' -Value 'C:\Windows\System32\schtasks.exe /run /tn RunAs\PSSysTrayLauncher' | Out-Null
    } Else {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PSSysTrayLauncher' -PropertyType 'string' -Value 'C:\Windows\System32\schtasks.exe /run /tn RunAs\PSSysTrayLauncher' | Out-Null}

    If ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').Property -contains 'PS_SysTray') {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PS_SysTray' -Value 'C:\Windows\System32\schtasks.exe /run /tn RunAs\PS_SysTray' | Out-Null
    } Else {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PS_SysTray' -PropertyType 'string' -Value 'C:\Windows\System32\schtasks.exe /run /tn RunAs\PS_SysTray' | Out-Null}

    if (Test-Path 'D:\SharedProfile\CloudStorage\Dropbox\#Profile\AdminTools\Start.exe') {
        If ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').Property -contains 'PortableApps') {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PortableApps' -Value 'D:\SharedProfile\CloudStorage\Dropbox\#Profile\AdminTools\Start.exe' | Out-Null
        } Else {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'PortableApps' -PropertyType 'string' -Value 'D:\SharedProfile\CloudStorage\Dropbox\#Profile\AdminTools\Start.exe' | Out-Null}
    }

 
    $DesktopIni = @'
[.ShellClassInfo]
IconResource=C:\Program Files\PSToolKit\icons\pool-3.ico,0
'@

    #Create/Add content to the desktop.ini file
    if (Test-Path (Join-Path -Path $Labtools.FullName -ChildPath '\desktop.ini')) {Remove-Item (Join-Path -Path $Labtools.FullName -ChildPath '\desktop.ini') -Force -ErrorAction SilentlyContinue}
    $newini = New-Item -Path (Join-Path -Path $Labtools.FullName -ChildPath '\desktop.ini') -ItemType File -Value $DesktopIni
  
    #Set the attributes for $DesktopIni
    $newini.Attributes = 'Hidden, System, Archive'
 
    #Finally, set the folder's attributes
    $Labtools.Attributes = 'ReadOnly, Directory'
    #endregion

    #region Update Local Modules
    Write-Host '[Checking]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'My Modules Versions' -ForegroundColor Cyan

    'CTXCloudApi', 'PSLauncher', 'XDHealthCheck', 'PSConfigFile' | ForEach-Object {
        $CheckMod = $_
        Write-Host "`t[Checking]: " -NoNewline -ForegroundColor Yellow; Write-Host "$($CheckMod)" -ForegroundColor Cyan

        Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Initial] Checking Nas Ver"
        $NasMod = (Get-ChildItem -Directory "\\dfnas\Profile\Utils\PSModules\$($CheckMod)" | Sort-Object -Property Name -Descending)[0]
        [version]$NasModver = $NasMod.Name

        try {
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Initial] Checking Local Ver"
            $LocalMod = (Get-ChildItem -Directory "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)" -ErrorAction Stop | Sort-Object -Property Name -Descending)[0].Name
        } catch {
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Creating] Local Dir"
            New-Item -Path "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)" -ItemType Directory -Force | Out-Null
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Copy] first instance"
            Copy-Item -Path $NasMod.FullName -Destination "C:\Program Files\WindowsPowerShell\Modules\$($ModuleName)\" -Force -Recurse
            $LocalMod = (Get-ChildItem -Directory "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)" -ErrorAction Stop | Sort-Object -Property Name -Descending)[0].Name
        }
        [version]$LocalModVer = $LocalMod.Name

        if ($LocalModVer -lt $NasModver) {
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Creating] backup zip"
            Get-ChildItem -Directory "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)" | Compress-Archive -DestinationPath "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)\$($CheckMod)-bck.zip" -Update
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Remove] Old Dir"
            Get-ChildItem -Directory "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)" | Remove-Item -Recurse -Force
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Copy] New dir"
            Copy-Item -Path $NasMod.FullName -Destination "C:\Program Files\WindowsPowerShell\Modules\$($CheckMod)\" -Force -Recurse
            Write-Verbose "$((Get-Date -Format HH:mm:ss).ToString()) [Complete]"
        }
    }
    #endregion
    #endregion

    Invoke-PSConfigFile -ConfigFile '\\vulcan.internal.lab\SharedProfile\CloudStorage\PSCustomConfig.json' -DisplayOutput
    Set-PSConfigFileExecution -PSProfile RemoveScript
    Set-PSConfigFileExecution -PSProfile AddScript

    Write-Host '[Update]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'Complete' -ForegroundColor Green
    Start-Sleep 30
}

$web = New-Object System.Net.WebClient
$web.DownloadFile('https://bit.ly/35sEu2b', "$($env:TEMP)\Start-PSToolkitSystemInitialize.ps1")
$full = Get-Item "$($env:TEMP)\Start-PSToolkitSystemInitialize.ps1"
Import-Module $full.FullName -Force
Start-PSToolkitSystemInitialize -LabSetup -InstallMyModules
Remove-Item $full.FullName

Set-LabSettingsOnly

#region Other Settings
Write-Host '[Set]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'Other Config' -ForegroundColor Cyan
Add-ChocolateyPrivateRepo -RepoName ProGet -RepoURL "http://progetserver.internal.lab/nuget/htpcza-choco" -Priority 1 -RepoApiKey "72dd0bb9ae376d6253ec16acb3805e6810a41551"
Invoke-PSConfigFile -ConfigFile "\\vulcan.internal.lab\SharedProfile\CloudStorage\PSCustomConfig.json" -DisplayOutput
Set-PSConfigFileExecution -PSProfile RemoveScript
Set-PSConfigFileExecution -PSProfile AddScript
Set-PSToolKitSystemSettings -RunAll
#endregion

Write-Host " "
Write-Host '[Complete]: ' -NoNewline -ForegroundColor Yellow; Write-Host 'All Tasks' -ForegroundColor DarkRed
Start-Sleep 30

#--- Uninstall unnecessary applications that come with Windows out of the box ---
Write-Host "Uninstall some applications that come with Windows out of the box" -ForegroundColor "Yellow"

function removeApp {
	Param ([string]$appName)
	Write-Output "Trying to remove $appName"
	Get-AppxPackage $appName -AllUsers | Remove-AppxPackage
	Get-AppXProvisionedPackage -Online | Where DisplayName -like $appName | Remove-AppxProvisionedPackage -Online
}

$applicationList = @(
	"Microsoft.BingFinance"
	"Microsoft.3DBuilder"
	"Microsoft.BingFinance"
	"Microsoft.BingNews"
	"Microsoft.BingSports"
	"Microsoft.BingWeather"
	"Microsoft.CommsPhone"
	"Microsoft.Getstarted"
	"Microsoft.WindowsMaps"
	"*MarchofEmpires*"
	"Microsoft.GetHelp"
	"Microsoft.Messaging"
	"*Minecraft*"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.OneConnect"
	"Microsoft.WindowsPhone"
	"Microsoft.WindowsSoundRecorder"
	"*Solitaire*"
	"Microsoft.MicrosoftStickyNotes"
	"Microsoft.Office.Sway"
	"Microsoft.XboxApp"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"
	"Microsoft.NetworkSpeedTest"
	"Microsoft.FreshPaint"
	"Microsoft.Print3D"
	"*Autodesk*"
	"*BubbleWitch*"
    "king.com*"
    "G5*"
	"*Dell*"
	"*Facebook*"
	"*Keeper*"
	"*Netflix*"
	"*Twitter*"
	"*Plex*"
	"*.Duolingo-LearnLanguagesforFree"
	"*.EclipseManager"
	"ActiproSoftwareLLC.562882FEEB491" # Code Writer
	"*.AdobePhotoshopExpress"
);

foreach ($app in $applicationList) {
    removeApp $app
}


Enable-UAC
Enable-MicrosoftUpdate
Install-WindowsUpdate -acceptEula
