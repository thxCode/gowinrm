#Requires -Version 5.0


# Configure a Windows host for remote management with GoWinRM
# -----------------------------------------------------------
#
# Background
# ----------
#
# This script learns inspiration from Ansible Windows Server Configuration, it can check
# the current Windows host configuration is able to allow GoWinRM to connect,
# authenticate and test.
#
# Usage
# -----
#
# This script have already tested in Windows Server 2016(1709), there is NO GUARANTEE that
# the previous still can work.
#
# Logging
# -------
#
# All events are logged to the Windows EventLog, it can review by "ps> Get-EventLog -LogName GoWinRMSetup".
# Run this script with an option "-Verbose" can see the verbose output messages.
#
# Authentication
# --------------
#
# By default, the WinRM authentication enables Basic, Kerberos and Negotiate.
# Use option "-OCredSSP", "-OCertificate", "-OBasic", "-OKerberos", "-ONegotiate" to enable
# corresponding type as an authentication option.
# Use option "-XCredSSP", "-XCertificate", "-XBasic", "-XKerberos", "-XNegotiate" to disable
# corresponding type as an authentication option.
#
# Security
# --------
#
# By default, the PowerShell doesn't allow the PUBLIC zone devices to access.
# Use option "-SkipNetworkProfileCheck" to skip the network profile check, and then
# the PowerShell can accept the accessing from DOMAIN, PRIVATE and PUBLIC zone.
#
# SSL Certificate
# ---------------
#
# The WinRM also supports HTTPS, this script defaults to allow HTTP and HTTPS.
# Use option "-XSSL" to disable using SSL.
#
# Use option "-CertThumbprint" to provide a SSL certificate thumbprint which exists in Cert:\LocalMachine\My
# Use option "-CertUseLocalIndex" to provide an index to choose one of the SSL certificate thumbprints which exist in Cert:\LocalMachine\My
# Use option "-CertValidityDays" to specify how long the new SSL certificate is valid starting from today.
# Use option "-CertForceNewSSL" to create a new SSL Certificate and be forced on the WinRM Listener
# when re-running this script. This is necessary when a new SID and CN name is created.
# Use option "-CertSubjectName" to specify the CN name of the new SSL certificate. This defaults to
# the system's hostname and generally should not be specified.


[CmdletBinding()]

Param (
    [switch]$OCredSSP = $false,
            $OCertificate = $false,
            $XBasic = $true,
            $XKerberos = $false,
            $XNegotiate = $false,
    [switch]$XCredSSP = $true,
            $XCertificate = $true,
            $OBasic = $false,
            $OKerberos = $true,
            $ONegotiate = $true,
    [switch]$SkipNetworkProfileCheck = $false,
    [switch]$XSSL = $false,
    [string]$CertThumbprint = "",
    [int]$CertUseLocalIndex = -1,
    [int]$CertValidityDays = 1095,
    [switch]$CertForceNewSSL = $false,
    [string]$SubjectName = $env:COMPUTERNAME,
    [string]$EventLogName = "GoWinRMSetup",
    [string]$EventSource = "PowerShell CLI"
)

Function log-debug {
    $message = $args[0]
    Write-Verbose "[DEBUG]: $message"
}

Function log-info {
    $message = $args[0]
    Write-Verbose "[INFO ]: $message"
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Information -EventId 1 -Message $message
}

Function log-warn {
    $message = $args[0]
    Write-Verbose "[WARN ]: $message"
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Warning -EventId 1 -Message $message
}

Function log-err {
    $message = $args[0]
    Write-Verbose "[ERROR]: $message"
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Error -EventId 1 -Message $message
}

Function check-identity {
    $currentPrincipal = new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Output "[ERROR]: You need elevated Administrator privileges in order to run this script."
        Write-Output "         Start Windows PowerShell by using the Run as Administrator option."
        Exit 2
    }
}

Function prepare-log {
    If ([System.Diagnostics.EventLog]::Exists($EventLogName) -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
        New-EventLog -LogName $EventLogName -Source $EventSource
    }
}

Function check-powershell {
    log-debug "Verifying PowerShell version."

    If ($PSVersionTable.PSVersion.Major -lt 5) {
        Throw "PowerShell version 5 or higher is required."
    }
}

Function check-winrm {
    log-debug "Verifying WinRM service."

    $svcWinRM = Get-Service "WinRM"
    If (!$svcWinRM) {
        Throw "Unable to find the WinRM service."
    } ElseIf ($svcWinRM.Status -ne "Running") {
        log-debug "Setting WinRM service to start automatically on boot."
        Set-Service -Name "WinRM" -StartupType Automatic
        log-info "Set WinRM service to start automatically on boot."
        log-debug "Starting WinRM service."
        Start-Service -Name "WinRM" -ErrorAction Stop
        log-info "Started WinRM service."
    }
}

Function check-powershell-remote {
    log-debug "Verifying PowerShell Remoting."

    If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
        If ($SkipNetworkProfileCheck) {
            log-debug "Enabling PS Remoting without checking Network profile."
            Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
            log-warn "Enabled PS Remoting without checking Network profile."
        } Else {
            log-debug "Enabling PS Remoting."
            Enable-PSRemoting -Force -ErrorAction Stop
            log-info "Enabled PS Remoting."
        }
    } Else {
        log-info "PS Remoting is already enabled."
    }
}

Function Detect-Requirements {
    check-identity

    prepare-log

    check-powershell

    check-winrm

    check-powershell-remote
}

Function Configure-Authentication {
    log-debug "Configuring WinRM Authentication."

    $authSetting = Get-ChildItem WSMan:\localhost\Service\Auth

    # Basic
    $basicAuthSetting = $authSetting | Where-Object {$_.Name -eq "Basic"}
    If ($OBasic -and (-not $XBasic)) {
        If (($basicAuthSetting.Vlue) -eq $true) {
            log-info "Basic auth is already enabled."
        } Else {
            log-debug "Enabling Basic auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
            log-info "Enabled Basic auth support."
        }
    } ElseIf ($XBasic -and (-not $OBasic)) {
        If (($basicAuthSetting.Value) -eq $false) {
            log-info "Basic auth is already disabled."
        } Else {
            log-debug "Disabling Basic auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
            log-info "Disabled Basic auth support."
        }
    } Else {
        log-warn "Conflicting parameters -OBasic -XBasic"
    }

    # Kerberos
    $kerberosAuthSetting = $authSetting | Where-Object {$_.Name -eq "Kerberos"}
    If ($OKerberos -and (-not $XKerberos)) {
        If (($kerberosAuthSetting.Value) -eq $true) {
            log-info "Kerberos auth is already enabled."
        } Else {
            log-debug "Enabling Kerberos auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Kerberos" -Value $true
            log-info "Enabled Kerberos auth support."
        }
    } ElseIf ($XKerberos -and (-not $OKerberos)) {
        If (($kerberosAuthSetting.Value) -eq $false) {
            log-info "Kerberos auth is already disabled."
        } Else {
            log-debug "Disabling Kerberos auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Kerberos" -Value $false
            log-info "Disabled Kerberos auth support."
        }
    } Else {
        log-warn "Conflicting parameters -OKerberos -XKerberos"
    }

    # Negotiate
    $negotiateAuthSetting = $authSetting | Where-Object {$_.Name -eq "Negotiate"}
    If ($ONegotiate -and (-not $XNegotiate)) {
    	If (($negotiateAuthSetting.Value) -eq $true) {
            log-info "Negotiate auth is already enabled."
        } Else {
            log-debug "Enabling Negotiate auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Negotiate" -Value $true
            log-info "Enabled Negotiate auth support."
        }
    } ElseIf ($XNegotiate -and (-not $ONegotiate)) {
    	If (($negotiateAuthSetting.Value) -eq $false) {
            log-info "Negotiate auth is already disabled."
        } Else {
            log-debug "Disabling Negotiate auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Negotiate" -Value $false
            log-info "Disabled Negotiate auth support."
        }
    } Else {
        log-warn "Conflicting parameters -ONegotiate -XNegotiate"
    }

    # Certificate
    $certificateAuthSetting = $authSetting | Where-Object {$_.Name -eq "Certificate"}
    If ($OCertificate -and (-not $XCertificate)) {
    	If (($certificateAuthSetting.Value) -eq $true) {
            log-info "Certificate auth is already enabled."
        } Else {
            log-debug "Enabling Certificate auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Certificate" -Value $true
            log-info "Enabled Certificate auth support."
        }
    } ElseIf ($XCertificate -and (-not $OCertificate)) {
    	If (($certificateAuthSetting.Value) -eq $false) {
            log-info "Certificate auth is already disabled."
        } Else {
            log-debug "Disabling Certificate auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Certificate" -Value $false
            log-info "Disabled Certificate auth support."
        }
    } Else {
        log-warn "Conflicting parameters -OCertificate -XCertificate"
    }

    # CredSSP
    $credSSPAuthSetting = $authSetting | Where-Object {$_.Name -eq "CredSSP"}
    If ($OCredSSP -and (-not $XCredSSP)) {
		If (($credSSPAuthSetting.Value) -eq $true) {
            log-info "CredSSP auth is already enabled."
        } Else {
            log-debug "Enabling CredSSP auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value $true
            log-info "Enabled CredSSP auth support."
        }
    } ElseIf ($XCredSSP -and (-not $OCredSSP)) {
    	If (($credSSPAuthSetting.Value) -eq $false) {
            log-info "CredSSP auth is already disabled."
        } Else {
            log-debug "Disabling CredSSP auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value $false
            log-info "Disabled CredSSP auth support."
        }
    } Else {
    	log-warn "Conflicting parameters -OCredSSP -XCredSSP"
    }

}

Function generate-cert {
    $cert = New-SelfSignedCertificate -Subject "CN=$SubjectName" -NotAfter $([datetime]::now.AddDays($CertValidityDays))

    return $cert.Thumbprint
}

Function get-local-cert {
    $thumbprints = Get-Childitem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$SubjectName" } | Select-Object -Property Thumbprint

    return @($thumbprints)[$CertUseLocalIndex].Thumbprint
}

Function add-winrm-ssl-listener {
    $thumbprint = ""

    If ($CertThumbprint) {
        $thumbprint = $CertThumbprint
    } ElseIf ($CertUseLocalIndex -gt -1) {
        $thumbprint = get-local-cert
    } ElseIf (-not $thumbprint) {
        $thumbprint = generate-cert
    }

    If (-not $thumbprint) {
        Throw "SSL certificate thumbprint is empty."
    }

    Write-Output "SSL certificate thumbprint: $thumbprint"

    $valueset = @{
        Hostname = $SubjectName
        CertificateThumbprint = $thumbprint
    }

    $selectorset = @{
        Transport = "HTTPS"
        Address = "*"
    }

    log-debug "Enabling newly SSL listener."
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    log-info "Enabled newly SSL listener."
}

Function delete-winrm-ssl-listener {
    $selectorset = @{
        Transport = "HTTPS"
        Address = "*"
    }

    log-debug "Disabling early SSL listener."
    Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset
    log-info "Disabled early SSL listener."
}

Function Configure-SSL {
    $httpsSetting = (Get-ChildItem WSMan:\localhost\Listener) | Where {$_.Keys -like "TRANSPORT=HTTPS"}

    # enable SSL
    If (-not $XSSL) {
        If (-not $httpsSetting) {
            log-debug "Enabling HTTPS."

            add-winrm-ssl-listener

            New-NetFirewallRule -Name 'allow-winrm-https' -Direction Inbound -DisplayName 'Allow WinRM HTTPS' -LocalPort 5986 -Protocol 'TCP'

            log-info "Enabled HTTPS."
        } ElseIf ($CertForceNewSSL) {
            log-debug "SSL is already active, overwriting the early SSL."

            delete-winrm-ssl-listener

            add-winrm-ssl-listener

            log-info "Overwrited SSL."
        } Else {
            log-info "SSL is already active."
        }
    } ElseIf (($XSSL) -and (-not $httpsSetting)) {
        log-debug "Disabling HTTPS."

        delete-winrm-ssl-listener

        Remove-NetFirewallRule -Name 'allow-winrm-https' -DisplayName 'Allow WinRM HTTPS'

        log-warn "Disabled HTTPS."
    } Else {
        log-warn "Disabled HTTPS."
    }
}

Function Verify-Configuration {
    log-debug "Verifying Configuration."

    $httpPSSession = New-PSSession -ComputerName "localhost" -ErrorVariable testHttpError -ErrorAction SilentlyContinue

    If ($httpPSSession) {
        If (($httpPSSession.State -eq "Opened") -and ($httpPSSession.Availability -eq "Available")) {
            log-info "Verify HTTP connecting: Success."
        } Else {
            log-warn "Verify HTTP connecting: Fail."
        }
        Remove-PSSession -Id $httpPSSession.Id -ErrorAction SilentlyContinue
    } Else {
        log-err "Verify HTTP connecting: Wrong, exception is $testHttpError.Exception"
    }

    If (-not $XSSL) {
        $httpsPSSessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $httpsPSSession = New-PSSession -ComputerName "localhost" -ErrorVariable testHttpsError -ErrorAction SilentlyContinue -UseSSL -SessionOption $httpsPSSessionOptions

        If ($httpsPSSession) {
            If (($httpsPSSession.State -eq "Opened") -and ($httpsPSSession.Availability -eq "Available")) {
                log-info "Verify HTTPS connecting: Success."
            } Else {
                log-warn "Verify HTTPS connecting: Fail."
            }
            Remove-PSSession -Id $httpsPSSession.Id -ErrorAction SilentlyContinue
        } Else {
            log-err "Verify HTTPS connecting: Wrong, exception is $testHttpsError.Exception"
        }
    }

}

# Main
$ErrorActionPreference = "Stop"

Trap {
    log-err $_
    Exit 1
}

Detect-Requirements

Configure-Authentication

Configure-SSL

Verify-Configuration

log-info "Configuration has been completed."
