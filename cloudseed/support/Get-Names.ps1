#!/usr/bin/pwsh
# Copyright (C) 2020 - 2023 iDigitalFlame
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

[Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
[Reflection.Assembly]::LoadWithPartialName("System.Drawing.Imaging") | Out-Null

Add-Type -TypeDefinition '
using System;
using System.Runtime.InteropServices;

public class Shell32 {
    [DllImport("shell32.dll", EntryPoint="ExtractIconExW", CharSet=CharSet.Unicode, ExactSpelling=true, CallingConvention=CallingConvention.StdCall)]
    public static extern int ExtractIconEx(string lpszFile, int iconIndex, out IntPtr phiconLarge, out IntPtr phiconSmall, int nIcons);
}
'
Add-Type -TypeDefinition '
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", EntryPoint="DestroyIcon")]
    public static extern int DestroyIcon(IntPtr hIcon);
}
'

function Export-Icons {
    param (
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "DLL or EXE with Icons to save."
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $File,
        [Parameter(
            Position = 1,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Directory to save the Icons."
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputDir
    )
    [System.IntPtr]$k = 0
    [System.IntPtr]$z = 0
    $p = Split-Path -Leaf $File
    $c = [Shell32]::ExtractIconEx($File, -1, [ref]$k, [ref]$z, 0)
    if ($c -le 0) {
        return
    }
    for ($i = 0; $i -lt $c; $i++) {
        $n = [Shell32]::ExtractIconEx($File, $i, [ref]$k, [ref]$z, 1)
        if ($n -ne 2) {
            continue
        }
        $x = [System.Drawing.Icon]::FromHandle($k).ToBitmap()
        $x.Save("$($OutputDir)\$($p)-$($i).ico", [System.Drawing.Imaging.ImageFormat]::Icon)
        [User32]::DestroyIcon($k) | Out-Null
        [User32]::DestroyIcon($z) | Out-Null
    }
}

function Export-NamesJSON {
    param (
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to save the resulting JSON."
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputFile,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to save the resulting Icons as files."
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $IconsDir = $null,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromRemainingArguments = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Directory paths to use for search indexing."
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $SearchPaths
    )
    $dirList = New-Object System.Collections.ArrayList
    foreach ($de in $SearchPaths) {
        $dirList.Add($de) | Out-Null
        foreach ($e in Get-ChildItem -Recurse -Path $de -Directory -ErrorAction Ignore -Force) {
            $z = $e.FullName.ToLower()
            if (
                $z.Contains("\windows\winsxs") -or
                $z.Contains("\windows\temp") -or
                $z.Contains("\windows\cursors") -or
                $z.Contains("\windows\servicing") -or
                $z.Contains("\windows\assembly") -or
                $z.Contains("\windows\rescache") -or
                $z.Contains("\windows\policydefinitions") -or
                $z.Contains("\windows\fonts") -or
                $z.Contains("\windows\shellnew") -or
                $z.Contains("\windows\tasks") -or
                $z.Contains("\windows\logs") -or
                $z.Contains("\windows\system32\catroot") -or
                $z.Contains("\windows\system32\driverstore\filerepository") -or
                $z.Contains("\modules\psdesiredstateconfiguration\dscresources") -or
                $z.Contains("\windows\system32\winevt\logs") -or
                $z.Contains("\program files\qemu-ga") -or
                $z.Contains("\program files\virtio-win") -or
                $z.Contains("\program files\windowspowershell") -or
                $z.Contains("\program files\windowsmail") -or
                $z.Contains("\program files\windowsapps") -or
                $z.Contains("\program files (x86)\qemu-ga") -or
                $z.Contains("\program files (x86)\virtio-win") -or
                $z.Contains("\program files (x86)\windowspowershell") -or
                $z.Contains("\program files (x86)\windowsmail") -or
                $z.Contains("\program files (x86)\windowsapps")
            ) {
                continue
            }
            $dirList.Add($e.FullName) | Out-Null
        }
    }
    $results = New-Object System.Collections.ArrayList
    $nameList = New-Object System.Collections.ArrayList
    $titleList = New-Object System.Collections.ArrayList
    $versionList = New-Object System.Collections.ArrayList
    foreach ($e in $dirList) {
        $dirFiles = Get-ChildItem -Path $e -ErrorAction Ignore -Force
        if ($null -eq $dirFiles -or $dirFiles.Length -eq 0) {
            continue
        }
        $dirHasExe = $false
        $dirExtList = New-Object System.Collections.ArrayList
        $dirNameList = New-Object System.Collections.ArrayList
        foreach ($i in $dirFiles) {
            if ($i.Name -eq "desktop.ini") {
                continue
            }
            $n = $i.Name.LastIndexOf(".")
            if ($n -le 1 -or ($i.Name.Length - $n) -ge 5) {
                continue
            }
            $ext = $i.Name.ToLower().Substring($n + 1)
            if (-not $dirExtList.Contains($ext)) {
                $dirExtList.Add($ext) | Out-Null
            }
            if ($ext -eq "exe" -or $ext -eq "dll" -or $ext -eq "sys") {
                if ($null -ne $i.VersionInfo.FileDescription) {
                    $title = $i.VersionInfo.FileDescription.ToString().Trim().Replace("&", "and").Replace("<", "[").Replace(">", "]")
                    if ($title.Length -gt 0 -and -not $title.Contains('"') -and -not $title.Contains("'") -and $title.Contains(" ") -and -not $titleList.Contains($title)) {
                        $titleList.Add($title) | Out-Null
                    }
                }
                if ($null -ne $i.VersionInfo.FileVersion) {
                    $ver = $i.VersionInfo.FileVersion.Trim()
                    if ($ver.IndexOf(" ") -gt 0) {
                        $ver = $ver.Substring(0, $ver.IndexOf(" "))
                    }
                    if ($ver.Length -gt 0 -and $ver.Contains(".") -and $ver.Split(".").Length -ge 4 -and -not ($ver -cmatch '[a-zA-Z]') -and $ver -match "^([0-9].)+$" -and -not $versionList.Contains($ver)) {
                        $versionList.Add($ver) | Out-Null
                    }
                }
                if ($null -ne $IconsDir) {
                    if (-not (Test-Path -Path $IconsDir)) {
                        New-Item -ItemType Directory -Path $IconsDir | Out-Null
                    }
                    Export-Icons -File $i.FullName -OutputDir $IconsDir
                }
                $dirHasExe = $true
            }
            $name = $i.Name.Substring(0, $n).Trim()
            if ($name.Length -le 3 -or $name.Contains("~") -or $name.Split("-").Count -gt 2) {
                continue
            }
            if ($name.Contains(".")) {
                $u = $i.Name.LastIndexOf(".")
                $name = $i.Name.Substring(0, $u).Trim()
            }
            if (-not $dirNameList.Contains($name)) {
                $dirNameList.Add($name) | Out-Null
            }
            if (-not $nameList.Contains($name)) {
                $nameList.Add($name) | Out-Null
            }
        }
        if ($dirExtList.Count -eq 0 -or $dirNameList.Count -eq 0) {
            continue
        }
        $results.Add((New-Object PSObject -Property @{
                    x86   = (-not $e.Contains("WOW64") -and -not $e.Contains("(x86)"))
                    exts  = $dirExtList
                    exec  = $dirHasExe
                    path  = $e
                    names = $dirNameList
                })) | Out-Null
    }
    Set-Content -Encoding UTF8 -Path $OutputFile -Value ((New-Object PSObject -Property @{
                paths    = $results
                names    = $nameList
                titles   = $titleList
                versions = $versionList
            }) | ConvertTo-Json -Depth 4)
}
