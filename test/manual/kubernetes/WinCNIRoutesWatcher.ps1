#Requires -Version 5.0


# Watch to add routes to all POD networks for NIC
# -----------------------------------------------
#
# Background
# ----------
# This script is used to assist ConfigureWinRM.ps1.
#
# Usage
# -----
# This script has already tested on Windows Server 2016(1709), there is NO GUARANTEE that
# the previous versions will be ok.
#
# Logging
# -------
# All events are logged to the Windows EventLog, it can review by "ps> Get-EventLog -LogName KubernetesNode -Source WinCNIWatcher".
# Use option "-LogLevel" to provide an integer to indicate the log level, 0-DEBUG, 1-INFO,
# 2-WARN, 3-ERROR.
#
# Network
# -------
# Use option "-VNICName" to specify the virtual NIC name.
# Use option "-HyperVSwitchNICName" to specify the Hyper-V vSwitch NIC name.

[CmdletBinding()]

Param (
    [ValidateSet(0, 1, 2, 3)]
    [parameter(Mandatory = $false)] [int]$LogLevel = 1,
    [parameter(Mandatory = $false)] [string]$EventLogName = "KubernetesNode",
    [parameter(Mandatory = $false)] [string]$EventSource = "WinCNIWatcher",
    
    [parameter(Mandatory = $true)] [string]$VNICName,
    [parameter(Mandatory = $true)] [string]$HyperVSwitchNICName
)

################ Tools ################ 

Function log-debug {
    If ($LogLevel -eq 0) {
        $message = $args[0]
        Write-Host -NoNewline -ForegroundColor DarkCyan "[DEBUG]: "
        Write-Host -ForegroundColor DarkCyan "$message"
    }
}

Function log-info {
    If (($LogLevel -ge 0) -and ($LogLevel -le 1)) {
        $message = $args[0]
        Write-Host -NoNewline "[ INFO]: "
        Write-Host "$message"
    }
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Information -EventId 1 -Message $message
}

Function log-warn {
    If (($LogLevel -ge 0) -and ($LogLevel -le 2)) {
        $message = $args[0]
        Write-Host -NoNewline -ForegroundColor Magenta "[ WARN]: "
        Write-Host -ForegroundColor Magenta "$message"
    }
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Warning -EventId 1 -Message $message
}

Function log-err {
    $message = $args[0]
    Write-Host -NoNewline -ForegroundColor Red "[ERROR]: "
    Write-Host -ForegroundColor Red "$message"
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Error -EventId 1 -Message $message
}

Function check-identity {
    $currentPrincipal = new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host -NoNewline -ForegroundColor Red "[ERROR]: "
        Write-Output "You need elevated Administrator privileges in order to run this script."
        Write-Output "         Start Windows PowerShell by using the Run as Administrator option."
        Exit 2
    }
}

Function prepare-log {
    If ([System.Diagnostics.EventLog]::Exists($EventLogName) -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
        $null = New-EventLog -LogName $EventLogName -Source $EventSource
    }
}

Function check-powershell {
    log-debug "Verifying PowerShell version."

    If ($PSVersionTable.PSVersion.Major -lt 5) {
        Throw "PowerShell version 5 or higher is required."
    }
}

Function download {
    param(
        [parameter(Mandatory = $true)] [string]$Url,
        [parameter(Mandatory = $true)] [string]$DestinationPath
    )

    [Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::SystemDefault, [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls12)
    Invoke-WebRequest -UseBasicParsing -OutFile $DestinationPath -Uri $Url -ErrorAction Stop
}

Function scrape {
    param(
        [parameter(Mandatory = $true)] [string]$Url
    )

    [Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::SystemDefault, [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls12)
    return Invoke-WebRequest -UseBasicParsing -Uri $Url -ErrorAction Stop
}

################ Private ################ 

Function detect-requirements {
    check-identity

    prepare-log

    check-powershell
}

################ Main ################ 

Trap {
    log-err $_
    popd
    Exit 1
}

detect-requirements

log-debug "VNICName is $VNICName."
log-debug "HyperVSwitchNICName is $HyperVSwitchNICName."
log-info "Watching to add routes to all POD networks on the Bridge endpoint nic and Hyper-V Switch nic."

$kconfigPath = [Environment]::GetEnvironmentVariable("KUBECONFIG", [EnvironmentVariableTarget]::User)
If (-not $kconfigPath) {
    log-err "The environment variable of kubeconfig file hasn't be setted."
}

While ($true) {
    pushd $env:ProgramFiles\kubernetes\node\bin
    $podCIDRs=(.\kubectl.exe --kubeconfig=$kconfigPath get nodes -o=custom-columns=Name:.status.nodeInfo.operatingSystem,podCIDR:.spec.podCIDR --no-headers)
    popd

    Foreach ($podcidr in $podCIDRs) {
        $tmp = $podcidr.Split(" ")
        $os = $tmp | select -First 1
        $cidr = $tmp | select -Last 1
        $cidrGw =  $cidr.substring(0,$cidr.lastIndexOf(".")) + ".1"

        if ($os -eq "windows") {
            $cidrGw = $cidr.substring(0,$cidr.lastIndexOf(".")) + ".2"
        }

        $route = Get-NetRoute -InterfaceAlias "$VNICName" -DestinationPrefix $cidr -ErrorAction Ignore
        if (-not $route) {
            log-info "Add route to $VNICName for remote $os node, Pod CIDR $cidr, GW $cidrGw."

            $null = New-NetRoute -InterfaceAlias "$VNICName" -DestinationPrefix $cidr -NextHop $cidrGw -Verbose:$false
        }

        $route = Get-NetRoute -InterfaceAlias "$HyperVSwitchNICName" -DestinationPrefix $cidr -ErrorAction Ignore
        if (-not $route) {
            log-info "Add route to $HyperVSwitchNICName for remote $os node, Pod CIDR $cidr, GW $cidrGw."

            $null = New-NetRoute -InterfaceAlias "$HyperVSwitchNICName" -DestinationPrefix $cidr -NextHop $cidrGw -Verbose:$false
        }
    }

    Start-Sleep -s 10
}
