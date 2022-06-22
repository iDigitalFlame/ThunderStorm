#!/usr/bin/pwsh


function Get-Names {
    $r = New-Object System.Collections.ArrayList
    foreach ($e in Get-ChildItem -Recurse -Path "C:\" -ErrorAction Ignore) {
        Write-Host $e
        $r.Add($e.F)
    }
    Write-Host $r.Count
}

Get-Names
