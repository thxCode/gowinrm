#Requires -Version 5.0


# Prepare a Windows host for Kubernetes node
# ------------------------------------------
#
# Background
# ----------
# This script learns inspiration from "Ansible Windows Server Configuration" and the fragments of "Kubernetes on Windows", 
# it will try to make the current Windows host become a Kubernetes node.
# Use option "-Reverse" to go back the preparation.
# Use option "-PurgeKubernetes" to drop Kubernetes binaries.
# Use option "-PurgeDocker" to drop Docker binaries.
#
# Usage
# -----
# This script has already tested on Windows Server 2016(1709), there is NO GUARANTEE that
# the previous versions will be ok.
#
# Logging
# -------
# All events are logged to the Windows EventLog, it can review by "ps> Get-EventLog -LogName KubernetesNode -Source Prepare".
# Use option "-LogLevel" to provide an integer to indicate the log level, 0-DEBUG, 1-INFO,
# 2-WARN, 3-ERROR.
#
# Host
# ----
# Use option "-HostName" to specify this host's name.
# Use option "-HostIP" to specify this host's IP.
#
# WinRM Authentication
# --------------------
# By default, the WinRM authentication enables Basic, Kerberos and Negotiate.
# Use option "-AuthCredSSP", "-AuthCertificate", "-AuthBasic", "-AuthKerberos"to enable
# corresponding type as an authentication option.
# Use option "-AuthCredSSP:$false", "-AuthCertificate:$false", "-AuthBasic:$false", "-AuthKerberos:$false" to disable
# corresponding type as an authentication option.
# Use option "-AuthCertificateGroup" to specify a local group name which must exist in host, "ps> Get-LocalGroup"
# Use option "-AuthCertificateUser" to specify a local user name, if the user doesn't exist, this script will
# create (s)he and append to "$AuthCertificateGroup", "ps> Get-LocalUser"
# Use option "-AuthCertificateUserDomain" to specify the domain of local user name.
# Use option "-AuthCertificateUserThumbprint" to provide a client certificate thumbprint
# hich exists in Cert:\LocalMachine\TrustedPeople
#
# WinRM SSL Certificate
# ---------------------
# The WinRM also supports HTTPS, this script defaults to allow HTTP and HTTPS.
# Use option "-SkipSSL" to disable using SSL.
#
# Use option "-SSLThumbprint" to provide a SSL certificate thumbprint which exists in Cert:\LocalMachine\My
# Use option "-NewCertValidityDays" to specify how long the new SSL certificate is valid starting from today.
# Use option "-NewCertForce" to create a new self-signed certificate and be forced on the WinRM Listener
# when re-running this script. This is necessary when a new SID and CN name is created.
# Use option "-NewCertOutputDir" to specify a path to export the server cacert and cert, default is $pwd.
#
# WinRM Security
# --------------
# By default, the PowerShell doesn't allow the PUBLIC zone devices to access.
# Use option "-SkipPSNetworkProfileCheck" to skip the network profile check, and then
# the PowerShell can accept the accessing from DOMAIN, PRIVATE and PUBLIC zone.
# Use option "-SkipEncryptedService" to connect the WinRM service withou encrypted, if don't use SSL.
#
# Network
# -------
# Use option "-NetworkHTTPProxy" to specify a proxy address for HTTP.
# Use option "-NetworkHTTPSProxy" to specify a proxy address for HTTP.
# Use option "-NetworkDNS" to append a group of DNS to the NIC.
# 
# Docker
# ------
# Use option "-DockerDownloadURL" to specify the download URL of Docker.
# Use option "-DockerRegistories" to append a group of Docker registories to Docker configuration.
# Use option "-DockerSupportLCOW" to enable Linux container supporting for Windows Docker [Experimental].
# Use option "-DockerDataRoot" to specify a location to save the Docker data.
#
# Kubernetes
# ----------
# Use option "-KubeDownloadURL" to specify the download URL of Kubernetes.
# Use option "-KubeContainerization" to RUN kubelet container and kube-proxy container instead of binary, which needs Docker version supporting [Experimental]. 


[CmdletBinding()]

Param (
    [parameter(Mandatory = $false)] [switch]$Reverse = $false,
    [parameter(Mandatory = $false)] [switch]$PurgeKubernetes = $false,
    [parameter(Mandatory = $false)] [switch]$PurgeDocker = $false,

    [ValidateSet(0, 1, 2, 3)]
    [parameter(Mandatory = $false)] [int]$LogLevel = 1,
    [parameter(Mandatory = $false)] [string]$EventLogName = "KubernetesNode",
    [parameter(Mandatory = $false)] [string]$EventSource = "Prepare",

    [parameter(Mandatory = $false)] [string]$HostName = ((Get-WmiObject win32_computersystem).DNSHostName),
    [parameter(Mandatory = $false)] [string]$HostIP = "127.0.0.1",

    [parameter(Mandatory = $false)] [switch]$AuthCredSSP = $false,
    [parameter(Mandatory = $false)] [switch]$AuthCertificate = $false,
    [parameter(Mandatory = $false)] [switch]$AuthBasic = $false,
    [parameter(Mandatory = $false)] [switch]$AuthKerberos = $true,
    [parameter(Mandatory = $false)] [string]$AuthCertificateGroup = "Administrators",
    [parameter(Mandatory = $false)] [string]$AuthCertificateUser = "Administrator",
    [parameter(Mandatory = $false)] [string]$AuthCertificateUserDomain = "localhost",
    [parameter(Mandatory = $false)] [string]$AuthCertificateUserThumbprint,

    [parameter(Mandatory = $false)] [switch]$SkipSSL = $false,
    [parameter(Mandatory = $false)] [string]$SSLThumbprint,
    [parameter(Mandatory = $false)] [int]$NewCertValidityDays = 1095,
    [parameter(Mandatory = $false)] [switch]$NewCertForce = $false,
    [parameter(Mandatory = $false)] [string]$NewCertOutputDir = $pwd,

    [parameter(Mandatory = $false)] [switch]$SkipPSNetworkProfileCheck = $false,
    [parameter(Mandatory = $false)] [switch]$SkipEncryptedService,

    [parameter(Mandatory = $false)] [string]$NetworkHTTPProxy,
    [parameter(Mandatory = $false)] [string]$NetworkHTTPSProxy,
    [parameter(Mandatory = $false)] [string[]]$NetworkDNS = @("1.1.1.1", "8.8.8.8"),

    [parameter(Mandatory = $false)] [string]$DockerDownloadURL = "https://download.docker.com/components/engine/windows-server/17.06/docker-17.06.2-ee-8.zip",
    [parameter(Mandatory = $false)] [string[]]$DockerRegistories,
    [parameter(Mandatory = $false)] [switch]$DockerSupportLCOW,
    [parameter(Mandatory = $false)] [string]$DockerDataRoot = "$env:ProgramData\docker",

    [parameter(Mandatory = $false)] [string]$KubeDownloadURL = "https://dl.k8s.io/v1.9.5/kubernetes-node-windows-amd64.tar.gz",
    [parameter(Mandatory = $false)] [switch]$KubeContainerization = $false
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

Function generate-client-certificate-thumbprint {
    Get-ChildItem Cert:\LocalMachine\Root\ | foreach {
        If ($_.Subject -eq "CN=$AuthCertificateUser") {
            Remove-Item -Force "Cert:\LocalMachine\My\$($_.Thumbprint)" -ErrorAction Ignore
            Remove-Item -Force "Cert:\LocalMachine\Root\$($_.Thumbprint)" -ErrorAction Ignore
            Remove-Item -Force "Cert:\LocalMachine\TrustedPeople\$($_.Thumbprint)" -ErrorAction Ignore
            Remove-Item -Force "Cert:\LocalMachine\CA\$($_.Thumbprint)" -ErrorAction Ignore
        }
    }

    $clientParams =  @{
        Type = 'Custom'
        Subject = "CN=$AuthCertificateUser"
        KeyLength = 2048
        KeyAlgorithm = 'RSA'
        HashAlgorithm = 'SHA256'
        NotAfter = (Get-Date).AddYears(100)
        KeyExportPolicy = 'Exportable'
        KeyUsage = 'DigitalSignature', 'KeyEncipherment'
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}UPN=$AuthCertificateUser@$AuthCertificateUserDomain")
    }
    $clientCA = New-SelfSignedCertificate @clientParams
    log-info "Created client CA for $AuthCertificateUser@$AuthCertificateUserDomain of $AuthCertificateGroup ."

    log-debug "Exporting winrm-client-$AuthCertificateUser cert.pem and key.pem to $NewCertOutputDir ."

    "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($clientCA.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), "InsertLineBreaks") + "`n-----END CERTIFICATE-----" | Out-File -Force -FilePath "$NewCertOutputDir\winrm-client-$AuthCertificateUser-cert.pem" -Encoding ascii
    pushd $env:TEMP
    Export-PfxCertificate -Cert $clientCA -FilePath "winrm-client-$AuthCertificateUser-cert.pfx" -Password (ConvertTo-SecureString -AsPlainText "changeit" -Force) | Out-Null
    Try {
        openssl.exe pkcs12 -in "winrm-client-$AuthCertificateUser-cert.pfx" -nocerts -nodes -out "$NewCertOutputDir\winrm-client-$AuthCertificateUser-key.pem" -password pass:changeit | Out-Null
    } Catch [System.Management.Automation.CommandNotFoundException] {
        $opensslPath = [Io.path]::Combine($env:ProgramFiles, "openssl", "openssl.exe")
        If (-not (Test-Path $opensslPath)) {
            download -Url http://www.indyproject.org/Sockets/fpc/AMD64-Win64OpenSSL-0_9_8g.zip -DestinationPath openssl.zip
            $null = Expand-Archive -Force openssl.zip -DestinationPath "$env:ProgramFiles\openssl\." -Verbose:$false -ErrorAction Stop | Out-Null
            $path = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
            If (-not $path.Contains("$env:ProgramFiles\openssl")) {
                $path += ";$env:ProgramFiles\openssl"

                [Environment]::SetEnvironmentVariable("PATH", $path, [EnvironmentVariableTarget]::Machine)
            }
        }

        pushd "$env:ProgramFiles\openssl"
        .\openssl.exe pkcs12 -in "$env:TEMP\winrm-client-$AuthCertificateUser-cert.pfx" -nocerts -nodes -out "$NewCertOutputDir\winrm-client-$AuthCertificateUser-key.pem" -password pass:changeit | Out-Null
        popd
    }
    Remove-Item -Force "winrm-client-$AuthCertificateUser-cert.pfx" -ErrorAction Ignore | Out-Null
    popd

    Export-Certificate -Cert $clientCA -Force -FilePath "$env:TEMP\winrm-client.crt" | Out-Null
    Import-Certificate -CertStoreLocation 'Cert:\LocalMachine\Root' -FilePath "$env:TEMP\winrm-client.crt" | Out-Null
    Import-Certificate -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' -FilePath "$env:TEMP\winrm-client.crt" | Out-Null
    Import-Certificate -CertStoreLocation 'Cert:\LocalMachine\CA' -FilePath "$env:TEMP\winrm-client.crt" | Out-Null
    Remove-Item -Force "$env:TEMP\winrm-client.crt" -ErrorAction Ignore | Out-Null

    log-info "Exported winrm-client-$AuthCertificateUser cert.pem and key.pem to $NewCertOutputDir ."

    return $clientCA.Thumbprint
}

Function configure-winrm-authentication {
    log-debug "Configuring WinRM Authentication."

    $authSetting = Get-ChildItem WSMan:\localhost\Service\Auth

    # Basic
    $basicAuthSetting = $authSetting | Where-Object {$_.Name -eq "Basic"}
    If ($AuthBasic) {
        If (($basicAuthSetting.Value) -eq $true) {
            log-info "Basic auth is already enabled."
        } Else {
            log-debug "Enabling Basic auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
            log-info "Enabled Basic auth support."
        }
    } Else {
        If (($basicAuthSetting.Value) -eq $false) {
            log-info "Basic auth is already disabled."
        } Else {
            log-debug "Disabling Basic auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
            log-info "Disabled Basic auth support."
        }
    }

    # Kerberos
    $kerberosAuthSetting = $authSetting | Where-Object {$_.Name -eq "Kerberos"}
    If ($AuthKerberos) {
        If (($kerberosAuthSetting.Value) -eq $true) {
            log-info "Kerberos auth is already enabled."
        } Else {
            log-debug "Enabling Kerberos auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Kerberos" -Value $true
            log-info "Enabled Kerberos auth support."
        }
    } Else {
        If (($kerberosAuthSetting.Value) -eq $false) {
            log-info "Kerberos auth is already disabled."
        } Else {
            log-debug "Disabling Kerberos auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Kerberos" -Value $false
            log-info "Disabled Kerberos auth support."
        }
    }

    # Certificate
    $certificateAuthSetting = $authSetting | Where-Object {$_.Name -eq "Certificate"}
    If ($AuthCertificate) {
        If ($SkipSSL) {
            Throw "Using Certificate authentication must work with SSL."
        }

        If (($certificateAuthSetting.Value) -eq $true) {
            log-info "Certificate auth is already enabled."
        } Else {
            log-debug "Enabling Certificate auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Certificate" -Value $true
            log-info "Enabled Certificate auth support."
        }

        $clientThumbprint = $null
        If ($AuthCertificateUserThumbprint) {
            $clientThumbprint = $AuthCertificateUserThumbprint
        } Else {
            $clientThumbprint = generate-client-certificate-thumbprint
        }
        log-info "Client certificate thumbprint: $clientThumbprint ."

        $currentPrincipal = new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        $credential = Get-Credential -UserName $currentPrincipal.Identities.Name -Message "Please login again to setup the client certificate."
        Get-ChildItem WSMan:\localhost\ClientCertificate | foreach {
            If (($_ | Get-ChildItem | ? Name -eq "Subject").Value -eq "$AuthCertificateUser@$AuthCertificateUserDomain") {
                $_ | Remove-Item -Recurse -Force -ErrorAction Ignore | Out-Null
            }
        }
        $null = New-Item -Path WSMan:\localhost\ClientCertificate -Subject "$AuthCertificateUser@$AuthCertificateUserDomain" -URI * -Issuer $clientThumbprint -Credential $credential -Force -ErrorAction Stop
    } Else {
        If (($certificateAuthSetting.Value) -eq $false) {
            log-info "Certificate auth is already disabled."
        } Else {
            log-debug "Disabling Certificate auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Certificate" -Value $false
            log-info "Disabled Certificate auth support."
        }
    }

    # CredSSP
    $credSSPAuthSetting = $authSetting | Where-Object {$_.Name -eq "CredSSP"}
    If ($AuthCredSSP) {
        Enable-WSManCredSSP -Role Server -Force -WarningAction Ignore -ErrorAction Ignore

        If (($credSSPAuthSetting.Value) -eq $true) {
            log-info "CredSSP auth is already enabled."
        } Else {
            log-debug "Enabling CredSSP auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value $true
            log-info "Enabled CredSSP auth support."
        }
    } Else {
        If (($credSSPAuthSetting.Value) -eq $false) {
            log-info "CredSSP auth is already disabled."
        } Else {
            log-debug "Disabling CredSSP auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value $false
            log-info "Disabled CredSSP auth support."
        }
    }
}

Function generate-cert {
    $validayDate = (Get-Date).AddDays($NewCertValidityDays)

    Get-ChildItem Cert:\LocalMachine\Root\ | foreach {
        If ($_.Subject -eq "CN=$HostName") {
            Remove-Item -Force "Cert:\LocalMachine\Root\$($_.Thumbprint)" -ErrorAction Ignore | Out-Null
            Remove-Item -Force "Cert:\LocalMachine\My\$($_.Thumbprint)" -ErrorAction Ignore | Out-Null
        }
    }

    $certParams = $null
    If ($HostIP) {
        $certParams = @{
            Subject = "CN=$HostName"
            KeyLength = 2048
            KeyAlgorithm = 'RSA'
            HashAlgorithm = 'SHA256'
            KeyExportPolicy = 'Exportable'
            NotAfter = $validayDate
            KeyUsage = 'DigitalSignature', 'DataEncipherment', 'KeyEncipherment', 'KeyAgreement'
            TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2", "2.5.29.17={text}IPAddress=$HostIP&DNS=$HostName")
        }
    } Else {
        $certParams = @{
            Subject = "CN=$HostName"
            KeyLength = 2048
            KeyAlgorithm = 'RSA'
            HashAlgorithm = 'SHA256'
            KeyExportPolicy = 'Exportable'
            NotAfter = $validayDate
            KeyUsage = 'DigitalSignature', 'DataEncipherment', 'KeyEncipherment', 'KeyAgreement'
            TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2", "2.5.29.17={text}DNS=$HostName")
        }
    }
    $cert = New-SelfSignedCertificate @certParams
    log-info "Created the server certificate."

    log-debug "Exporting winrm-server cert.pem to $NewCertOutputDir ."

    "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), "InsertLineBreaks") + "`n-----END CERTIFICATE-----" | Out-File -Force -FilePath "$NewCertOutputDir\winrm-server-cert.pem" -Encoding ascii

    ## import the serverCA to rootCert
    Export-Certificate -Cert $cert -Force -FilePath "$env:TEMP\winrm-server-cert.crt" | Out-Null
    Import-Certificate -CertStoreLocation 'Cert:\LocalMachine\Root' -FilePath "$env:TEMP\winrm-server-cert.crt" | Out-Null
    Remove-Item -Force "$env:TEMP\winrm-server-cert.crt" -ErrorAction Ignore | Out-Null

    log-info "Exported winrm-server cert.pem to $NewCertOutputDir ."

    return $cert.Thumbprint
}

Function add-winrm-ssl-listener {
    $thumbprint = ""

    If ($SSLThumbprint) {
        $thumbprint = $SSLThumbprint
    } ElseIf (-not $thumbprint) {
        $thumbprint = generate-cert
    }

    If (-not $thumbprint) {
        Throw "Server certificate thumbprint is empty."
    }

    log-info "Server certificate thumbprint: $thumbprint ."

    $valueset = @{
        Hostname = $HostName
        CertificateThumbprint = $thumbprint
    }

    $selectorset = @{
        Transport = "HTTPS"
        Address = "*"
    }

    log-debug "Enabling newly SSL listener."
    $null = New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset -ErrorAction Stop
    $httpsRule = Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' -ErrorAction Ignore
    If ($httpsRule) {
        Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' -Direction Inbound -LocalPort 5986 -Protocol 'TCP' -Action Allow -Verbose:$false -WarningAction Ignore -ErrorAction Ignore | Out-Null
    } Else {
        $null = New-NetFirewallRule -Group '@FirewallAPI.dll,-30267' -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]' -Name 'WINRM-HTTPS-In-TCP-ANY' -DisplayName 'Windows Remote Management (HTTPS-In)' -Direction Inbound -LocalPort 5986 -Protocol 'TCP' -Profile Any -Action Allow -Verbose:$false -WarningAction Ignore -ErrorAction Ignore
    }
    log-info "Enabled newly SSL listener."
}

Function delete-winrm-ssl-listener {
    $selectorset = @{
        Transport = "HTTPS"
        Address = "*"
    }

    $wsmanInstance = Get-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ErrorAction Ignore
    If ($wsmanInstance) {
        Remove-Item -Force "Cert:\LocalMachine\Root\$($wsmanInstance.CertificateThumbprint)" -ErrorAction Ignore
        Remove-Item -Force "Cert:\LocalMachine\My\$($wsmanInstance.CertificateThumbprint)" -ErrorAction Ignore

        log-debug "Disabling early SSL listener."
        Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ErrorAction Ignore | Out-Null
        Remove-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' -Verbose:$false -WarningAction Ignore -ErrorAction Ignore | Out-Null
        log-info "Disabled early SSL listener."
    }
}

Function configure-winrm-ssl {
    $httpsSetting = (Get-ChildItem WSMan:\localhost\Listener) | Where {$_.Keys -like "TRANSPORT=HTTPS"}

    # enable SSL
    If (-not $SkipSSL) {
        If (-not $httpsSetting) {
            log-debug "Enabling HTTPS."

            add-winrm-ssl-listener

            log-info "Enabled HTTPS."
        } ElseIf ($NewCertForce) {
            log-debug "SSL is already active, overwriting the early certificate."

            delete-winrm-ssl-listener

            add-winrm-ssl-listener

            log-info "Overwrited SSL."
        } Else {
            log-info "SSL is already active."
        }
    } Else {
        If ($httpsSetting) {
            log-debug "Disabling HTTPS."

            delete-winrm-ssl-listener

            log-warn "Disabled HTTPS."
        } Else {
            log-warn "Disabled HTTPS."
        }
    }
}

Function verify-winrm-service {
     log-debug "Verifying Configuration."

     $httpwsman = Test-WSMan -ComputerName $HostIP -ErrorVariable testHttpError -ErrorAction SilentlyContinue
     If ($httpwsman) {
        log-info "Verify HTTP connecting: Success."
     } Else {
         log-warn "Verify HTTP connecting: Wrong, exception is $($testHttpError.Exception)"
     }

     If (-not $SkipSSL) {
         $httpswsman = Test-WSMan -ComputerName $HostIP -UseSSL -ErrorVariable testHttpsError -ErrorAction SilentlyContinue
         If ($httpswsman) {
            log-info "Verify HTTPS connecting: Success."
         } Else {
             log-warn "Verify HTTPS connecting: Wrong, exception is $($testHttpsError.Exception)"
         }
     }
}

Function configure-winrm-service {
    log-debug "Verifying WinRM service."

    $svcWinRM = Get-Service -Name "WinRM" -ErrorAction Ignore
    If (-not $svcWinRM) {
        Throw "Unable to find the WinRM service."
    } ElseIf ($svcWinRM.Status -ne "Running") {
        log-debug "Setting WinRM service to start automatically on boot."
        Set-Service -Name "WinRM" -StartupType Automatic
        log-info "Set WinRM service to start automatically on boot."
        log-debug "Starting WinRM service."
        Start-Service -Name "WinRM" -ErrorAction Stop
        log-info "Started WinRM service."
    }

    $httpRule = Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -ErrorAction Ignore
    If ($httpRule) {
        Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -Direction Inbound -LocalPort 5985 -Action Allow -Verbose:$false -WarningAction Ignore -ErrorAction Ignore | Out-Null
    } Else {
        $null = New-NetFirewallRule -Group '@FirewallAPI.dll,-30267' -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]' -Name 'WINRM-HTTP-In-TCP-ANY' -DisplayName 'Windows Remote Management (HTTP-In)' -Direction Inbound -LocalPort 5985 -Protocol 'TCP' -Profile Any -Action Allow -Verbose:$false -WarningAction Ignore -ErrorAction Ignore
    }

    ## start: configure winrm
    configure-winrm-authentication

    configure-winrm-ssl

    If ($SkipEncryptedService) {
        Set-WSManInstance WinRM/Config/Service -ValueSet @{AllowUnencrypted = $true} | Out-Null
    } Else {
        Set-WSManInstance WinRM/Config/Service -ValueSet @{AllowUnencrypted = $false} | Out-Null
    }

    Set-WSManInstance WinRM/Config/Client -ValueSet @{TrustedHosts = "*"} | Out-Null
    ## end: configure winrm

    log-debug "Verifying PowerShell Remoting."
    If ($SkipPSNetworkProfileCheck) {
        log-debug "Enabling PS Remoting without checking Network profile."
        Enable-PSRemoting -SkipPSNetworkProfileCheck -Force -ErrorAction Stop
        log-warn "Enabled PS Remoting without checking Network profile."
    } Else {
        log-debug "Enabling PS Remoting."
        Enable-PSRemoting -Force -ErrorAction Stop
        log-info "Enabled PS Remoting."
    }

    verify-winrm-service
}

Function configure-dns {
    Get-DnsClientServerAddress -AddressFamily IPv4 | ? InterfaceAlias -NotLike "Loopback*" | foreach {
        $serverAddresses = $_.ServerAddresses
        $serverAddressesStr = $serverAddresses -join ","

        $NetworkDNS | foreach {
            If (-not ($serverAddresses -contains $_)) {
                $serverAddressesStr = $_ + "," + $serverAddressesStr
            }
        }

        Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $serverAddressesStr
    }

    Clear-DnsClientCache 
}

Function configure-network {
    If ($NetworkHTTPProxy) {
        [Environment]::SetEnvironmentVariable("HTTP_PROXY", $NetworkHTTPProxy, [EnvironmentVariableTarget]::Machine)
    }

    If ($NetworkHTTPSProxy) {
        [Environment]::SetEnvironmentVariable("HTTPS_PROXY", $NetworkHTTPSProxy, [EnvironmentVariableTarget]::Machine)
    }

    configure-dns
}

Function configure-docker-config {
    mkdir -p $env:ProgramData\docker\config -ErrorAction Ignore | Out-Null

    $dockerConfigPath = "$env:ProgramData\docker\config\daemon.json"
    $dockerConfigChangeFlag = $false
    $dockerConfig = @{}

    If (Test-Path $dockerConfigPath) {
        $dockerConfig = Get-Content $dockerConfigPath | ConvertFrom-Json
    }

    ## registory
    If ($DockerRegistories) {
        $registoryMirrors = $dockerConfig.'registry-mirrors'
        If (-not $registoryMirrors) {
            $registoryMirrors = @()
        }

        $DockerRegistories | foreach {
            If (-not ($registoryMirrors -contains $_)) {
                $registoryMirrors += @($_)

                log-debug "Appended docker config 'registry-mirrors' with $_ ."

                $dockerConfigChangeFlag = $true
            }
        }
        
        $dockerConfig | Add-Member @{'registry-mirrors'=$registoryMirrors} -Force
    }

    ## experimental
    If ($dockerConfig.experimental) {
        If ($DockerSupportLCOW -eq $false) {
            $dockerConfig | Add-Member @{'experimental'=$false} -Force
            log-debug "Setted docker config 'experimental' on False."

            $dockerConfigChangeFlag = $true
        }
    } ElseIf ($DockerSupportLCOW -eq $true) {
        $dockerConfig | Add-Member @{'experimental'=$true} -Force
        log-debug "Setted docker config 'experimental' on True."

        $dockerConfigChangeFlag = $true
    }

    ## data-root
    If ($DockerDataRoot) {
        If ($dockerConfig.'data-root' -ne $DockerDataRoot) {
            $dockerConfig | Add-Member @{'data-root'=$DockerDataRoot} -Force
            log-debug "Setted docker config 'data-root' on $DockerDataRoot ."

            $dockerConfigChangeFlag = $true
        }
    }

    If ($dockerConfigChangeFlag) {
        $dockerConfig | ConvertTo-Json -Compress -Depth 8 | Out-File -Encoding ascii -Force -FilePath $dockerConfigPath
    }

    return $dockerConfigChangeFlag
}

Function configure-docker-service {
    log-debug "Verifying Docker."

    $hostRestartFlag = $false

    ## Install Hyper-V Feature
    $hyperVFeature = Get-WindowsFeature -Name "Hyper-V"
    If ($hyperVFeature) {
        If (-not $hyperVFeature.Installed) {
            log-debug "Installing Hyper-V Windows feature."

            Install-WindowsFeature -Name "Hyper-V" -WarningAction Ignore -ErrorAction Stop | Out-Null

            log-info "Installed Hyper-V Windows feature."

            $hostRestartFlag = $true
        } Else {
            log-info "Hyper-V Windows feature is already installed."
        }
    } Else {
        Throw "Hyper-V Windows feature must be available."
    }

    ## Install Containers Feature
    $hyperVPSFeature = Get-WindowsFeature -Name "Hyper-V-PowerShell"
    If ($hyperVPSFeature) {
        If (-not $hyperVPSFeature.Installed) {
            log-debug "Installing Hyper-V-PowerShell Windows feature."

            Install-WindowsFeature -Name "Hyper-V-PowerShell" -WarningAction Ignore -ErrorAction Stop | Out-Null

            log-info "Installed Hyper-V-PowerShell Windows feature."
        } Else {
            log-info "Hyper-V-PowerShell Windows feature is already installed."
        }
    } Else {
        Throw "Hyper-V-PowerShell Windows feature must be available."
    }

    ## Install Containers Feature
    $containersFeature = Get-WindowsFeature -Name "Containers"
    If ($containersFeature) {
        If (-not $containersFeature.Installed) {
            log-debug "Installing Containers Windows feature."

            Install-WindowsFeature -Name "Containers" -WarningAction Ignore -ErrorAction Stop | Out-Null

            log-info "Installed Containers Windows feature."

            $hostRestartFlag = $true
        } Else {
            log-info "Containers Windows feature is already installed."
        }
    } Else {
        Throw "Containers Windows feature must be available."
    }

    ## Install LCOW
    If ($DockerSupportLCOW) {
        $initrdImgPath = [Io.path]::Combine($env:ProgramFiles, "Linux Containers", "initrd.img")
        $bootx64EfiPath = [Io.path]::Combine($env:ProgramFiles, "Linux Containers", "bootx64.efi")
        If ((-not (Test-Path $initrdImgPath)) -or (-not (Test-Path $bootx64EfiPath))) {
            log-debug "Downloading linuxkit/lcow."

            download -Url "https://github.com/linuxkit/lcow/releases/download/4.14.29-0aea33bc/release.zip" -DestinationPath $env:TEMP\lcow.zip
            $null = Expand-Archive -Force $env:TEMP\lcow.zip -DestinationPath "$env:ProgramFiles\Linux Containers\." -Verbose:$false -ErrorAction Stop | Out-Null
            rm $env:TEMP\lcow.zip -Force -Recurse -ErrorAction Ignore

            log-info "Downloaded linuxkit/lcow."
        }
    }

    ## Install Docker
    $dockerService = Get-Service -Name "docker" -ErrorAction Ignore
    If (-not $dockerService) {
        $dockerPath = [Io.path]::Combine($env:ProgramFiles, "docker", "docker.exe")
        $dockerdPath = [Io.path]::Combine($env:ProgramFiles, "docker", "dockerd.exe")
        If ((-not (Test-Path $dockerPath)) -or (-not (Test-Path $dockerdPath))) {
            If (-not $DockerDownloadURL) {
                $stableDokcerVersions = scrape -Url "https://download.docker.com/win/static/stable/x86_64/"
                $DockerDownloadURL = "https://download.docker.com/win/static/stable/x86_64/$($stableDokcerVersions.Links[-1].href)"
            }

            log-debug "Downloading Docker package zip from $DockerDownloadURL."

            download -Url $DockerDownloadURL -DestinationPath $env:TEMP\docker.zip
            $null = Expand-Archive -Force $env:TEMP\docker.zip -DestinationPath $env:ProgramFiles -Verbose:$false -ErrorAction Stop | Out-Null
            rm $env:TEMP\docker.zip -Force -Recurse -ErrorAction Ignore
            
            log-info "Downloaded Docker pakcage zip."
        }

        $path = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
        If (-not $path.Contains("$env:ProgramFiles\docker")) {
            $path += ";$env:ProgramFiles\docker"

            [Environment]::SetEnvironmentVariable("PATH", $path, [EnvironmentVariableTarget]::Machine)
        }

        pushd $env:ProgramFiles\docker
        .\dockerd.exe --register-service | Out-Null
        popd

        configure-docker-config

        Set-Service -Name "docker" -StartMode Automatic -ErrorAction Ignore

        $hostRestartFlag = $true
    } Else {
        log-info "Docker is already installed."

        If ($dockerService.StartType -ne "Automatic") {
            Set-Service -Name "docker" -StartMode Automatic -ErrorAction Ignore
        }

        $dockerNeedRestart = configure-docker-config

        Try {
            If ($dockerService.Status -ne "Running") {
                $dockerService | Start-Service 
            } ElseIf ($dockerNeedRestart) {
                $dockerService | Restart-Service
            }
        } Catch {
            $hostRestartFlag = $true
            log-warn "Cannot (re)start Docker service."
        }
    }

    return $hostRestartFlag
}

Function download-kubenretes-node-binaries {
    $kubePath = "$env:ProgramFiles\kubernetes\node\bin"

    $kubeletPath = [Io.path]::Combine($kubePath , "kubelet.exe")
    $kubectlPath = [Io.path]::Combine($kubePath , "kubectl.exe")
    $kubeProxyPath = [Io.path]::Combine($kubePath , "kube-proxy.exe")
    If ((-not (Test-Path $kubeletPath)) -or (-not (Test-Path $kubectlPath)) -or (-not (Test-Path $kubeProxyPath))) {
        pushd $env:TEMP

        ## download the tartool
        download -Url "https://github.com/senthilrajasek/tartool/releases/download/1.0.0/TarTool.zip" -DestinationPath tartool.zip
        ## Install .NET 3 Feature
        $netFrameworkFeature = Get-WindowsFeature -Name "NET-Framework-Features"
        If ($netFrameworkFeature) {
            If (-not $netFrameworkFeature.Installed) {
                log-debug "Installing NET-Framework-Features Windows feature."

                Install-WindowsFeature -Name "NET-Framework-Features" -WarningAction Ignore -ErrorAction Stop | Out-Null

                log-info "Installed NET-Framework-Features Windows feature."
            } Else {
                log-info "NET-Framework-Features Windows feature is already installed."
            }
        } Else {
            Throw "NET-Framework-Features Windows feature must be available."
        }
        $null = Expand-Archive -Force tartool.zip -ErrorAction Stop 

        log-debug "Downloading Kubernetes package tar.gz from $KubeDownloadURL."
        If ($KubeDownloadURL) {
            download -Url $KubeDownloadURL -DestinationPath kubernetes.tar.gz
        } Else {
            download -Url "https://dl.k8s.io/v1.9.7/kubernetes-node-windows-amd64.tar.gz" -DestinationPath kubernetes.tar.gz
        }
        log-info "Downloaded Kubernetes package tar.gz."

        pushd tartool
        .\TarTool.exe $env:TEMP\kubernetes.tar.gz $env:ProgramFiles
        popd

        ## Clean up
        rm tartool.zip -Force -ErrorAction Ignore
        rm tartool -Force -Recurse -ErrorAction Ignore
        rm kubernetes.tar.gz -Force -ErrorAction Ignore

        popd
    } Else {
        log-info "Kubernetes binaries are already downloaded."
    }

    ## Configure environment variable
    $path = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
    If (-not $path.Contains("$kubePath")) {
        $path += ";$kubePath"

        [Environment]::SetEnvironmentVariable("PATH", $path, [EnvironmentVariableTarget]::Machine)
    }
}

Function configure-kubernetes-node-service {
    log-debug "Verifying Kubernetes node binaries."

    mkdir -p $env:ProgramFiles\kubernetes -ErrorAction Ignore | Out-Null
    mkdir -p $env:ProgramData\kubernetes -ErrorAction Ignore | Out-Null
    
    If ($KubeContainerization) {
        $dockerServerVersion = docker version -f '{{.Server.APIVersion}}'
        $dockerServerSimpleVersion = ([regex]::Match($dockerServerVersion, '(\d+\.\d+)') | %{$_.Value})
        If ($dockerServerSimpleVersion) {
            If ($dockerServerSimpleVersion -lt 1.35) {
                Throw "The api version $dockerServerVersion of Docker server cannot run the containerization Kubernetes node components."
            } Else {
                Throw "Kubernetes node containerization components are not currently supported."
            }
        } Else {
            Throw "Cannot detect the Docker server version."
        }
    } Else {
        download-kubenretes-node-binaries
    }

}

################ Main ################ 

Trap {
    log-err $_
    Exit 1
}
$ErrorActionPreference = "Stop"

detect-requirements

If ($Reverse) {
    
    $svcWinRM = Get-Service "WinRM" -ErrorAction Ignore
    If (($svcWinRM) -and ($svcWinRM.Status -ne "Stopped")) {
        log-debug "Stopping WinRM service."

        log-debug "Disabling PS Remoting."
        Disable-PSRemoting -Force -WarningAction Ignore -ErrorAction Ignore
        log-info "Disabled PS Remoting."
    
        delete-winrm-ssl-listener

        Remove-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -Verbose:$false -WarningAction Ignore -ErrorAction Ignore | Out-Null

        Set-Service -Name "WinRM" -StartupType Manual -WarningAction Ignore -ErrorAction Ignore
        Stop-Service -Name "WinRM" -WarningAction Ignore -ErrorAction Ignore
    
        log-warn "Stopped WinRM service."
    }

    If ($PurgeDocker) {
        log-debug "Purging Docker."

        $dockerService = Get-Service -Name "docker" -ErrorAction Ignore
        If ($dockerService.Status -eq "Running") {
            docker system prune -a -f | Out-Null
        }

        Stop-Service -Name "docker" -ErrorAction Ignore  -WarningAction Ignore | Out-Null

        $service = Get-WmiObject -Class Win32_Service | ? Name -Like "docker"
        If ($service) {
            $service.delete() | Out-Null
        }

        If (Test-Path "$env:ProgramData\docker") {
            rm "$env:ProgramData\docker" -Force -Recurse -ErrorAction Ignore
        }

        If (Test-Path "$env:ProgramFiles\docker") {
            rm "$env:ProgramFiles\docker" -Force -Recurse -ErrorAction Ignore
        }

        If (Test-Path "$env:ProgramFiles\Linux Containers") {
            rm "$env:ProgramFiles\Linux Containers" -Force -Recurse -ErrorAction Ignore
        }

        log-warn "Purged Docker."
    }

    If ($PurgeKubernetes) {
        log-debug "Purging Kubernetes."

        If (Test-Path "$env:ProgramData\kubernetes") {
            rm "$env:ProgramData\kubernetes" -Force -Recurse -ErrorAction Ignore
        }
        If (Test-Path "$env:ProgramFiles\kubernetes") {
            rm "$env:ProgramFiles\kubernetes" -Force -Recurse -ErrorAction Ignore
        }

        log-warn "Purged Kubernetes."
    }
    
    log-info "Reversing Kuberentes node configuration has been completed."

} Else {

    configure-winrm-service

    configure-network

    $hostRestartFlag = configure-docker-service

    configure-kubernetes-node-service

    log-info "Kuberentes node has been prepared."

    If ($hostRestartFlag) {
        log-warn "Restart the host after 10 seconds."
        Start-Sleep -s 10
        Restart-Computer -Force -ErrorAction Stop
    }

}

