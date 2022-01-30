# Description: Boxstarter Script
# Author: Microsoft
# Common dev settings for machine learning using only Windows native tools

Disable-UAC

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

if ((Test-Path -Path C:\Utils) -eq $false) { New-Item -Path C:\Utils -ItemType Directory -Force -ErrorAction SilentlyContinue }
if ((Test-Path C:\Utils\LabScripts) -and ($null -eq (Get-Item C:\Utils\LabScripts).LinkType)) {
Rename-Item -Path   C:\Utils\LabScripts -NewName  C:\Utils\LabScripts-old
}
if (!(Test-Path C:\Utils\LabScripts)) {
New-Item -ItemType SymbolicLink -Name LabScripts -Path C:\Utils -Value '\\dfnas.internal.lab\Profile\Utils\LabScripts'
}

if ((Test-Path C:\Utils\PSModules) -and ($null -eq (Get-Item C:\Utils\PSModules).LinkType)) {
Rename-Item -Path   C:\Utils\PSModules -NewName  C:\Utils\PSModules-old
}
if (!(Test-Path C:\Utils\PSModules)) {
New-Item -ItemType SymbolicLink -Name PSModules -Path C:\Utils -Value '\\dfnas.internal.lab\Profile\Utils\PSModules'
}

Write-Host '[Installing]: ' -NoNewline -ForegroundColor Cyan; Write-Host 'Needed Powershell modules' -ForegroundColor Yellow
Install-Module ImportExcel, PSWriteHTML, PSWriteColor, PSScriptTools, PoshRegistry -Scope AllUsers -Force

Get-ChildItem C:\Utils\PSModules\*.psm1 -Recurse | ForEach-Object {
    Write-Host '[Importing]: ' -NoNewline -ForegroundColor Cyan; Write-Host $($_.FullName) -ForegroundColor Yellow
    Import-Module -Global -FullyQualifiedName $_.FullName -Force
    }

Set-PrivateRepositorySystemSettings -RunAll
Install-PSModules -BaseModules
Install-PS7

#--- Setting up Windows ---
executeScript "SystemConfiguration.ps1";
executeScript "FileExplorerSettings.ps1";
executeScript "RemoveDefaultApps.ps1";
executeScript "HyperV.ps1";
executeScript "GetMLIDEAndTooling.ps1";
executeScript "Docker.ps1";
executeScript "CommonDevTools.ps1";
executeScript "Browsers.ps1";

Install-ChocolateyApps -BaseApps



Enable-UAC
Enable-MicrosoftUpdate
Install-WindowsUpdate -acceptEula
