#Requires -Version 5.0


# Configure a Windows host for Kubernetes node
# --------------------------------------------
#
# Background
# ----------
# This script can configure the current Windows host as a Kubernetes node.
# Use option "-Reverse" to turn off the Kubernetes node.
#
# Usage
# -----
# This script has already tested on Windows Server 2016(1709), there is NO GUARANTEE that
# the previous versions will be ok.
#
# Logging
# -------
# All events are logged to the Windows EventLog, it can review by "ps> Get-EventLog -LogName KubernetesNode -Source Configure".
# Use option "-LogLevel" to provide an integer to indicate the log level, 0-DEBUG, 1-INFO,
# 2-WARN, 3-ERROR.
#
#
# Kubernetes
# ----------
# Use option "-KubeContainerization" to RUN kubelet container and kube-proxy container instead of binary, which needs Docker version supporting. 
# Use option "-KubeConfig" to specify the location or the base64 enconding content of kubeconfig.
# Use option "-KubeMasterIP" to specify the Kuberentes Linux master node IP, i.e. "192.168.1.37".
# Use option "-KubeClusterCIDR" to specify the Kubernetes cluster(Pod) CIDR, as same as the configuration of master node, i.e "10.100.0.0/16"
# Use option "-KubeServiceCIDR" to specify the Kubernetes SVC CIDR, as same as the configuration of master node, i.e. "10.0.0.0/16".
# Use option "-KubeDnsSuffix" to specify the Kubernetes DNS suffix, i.e. "svc.cluster.local".
# Use option "-KubeDnsServiceIP" to specify the Kubernetes DNS SVC IP, i.e. "10.0.0.10".
# Use option "-KubeVMSwitchName" to specify an external VMSwitch name, i.e. "k8s-cbr0", you can query VMSwitch name by "PS> Get-VMSwitch".
# Use option "-KubeCNIComponent" to specify a CNI component to use, i.e. "WinCNI".
# Use option "-KubeCNIMode" to specify the work mode of CNI component, i.e. "L2Bridge".
# Use option "-KubeLogLevel" to specify the log level of kubelet and kube-proxy.


[CmdletBinding()]

Param (
    [parameter(Mandatory = $false)] [switch]$Reverse = $false,

    [ValidateSet(0, 1, 2, 3)]
    [parameter(Mandatory = $false)] [int]$LogLevel = 1,
    [parameter(Mandatory = $false)] [string]$EventLogName = "KubernetesNode",
    [parameter(Mandatory = $false)] [string]$EventSource = "Configure",

    [parameter(Mandatory = $false)] [switch]$KubeContainerization = $false,
    [parameter(Mandatory = $false)] [string]$KubeMasterIP,
    [parameter(Mandatory = $false)] [string]$KubeClusterCIDR,
    [parameter(Mandatory = $false)] [string]$KubeServiceCIDR,
    [parameter(Mandatory = $false)] [string]$KubeDnsServiceIP,
    [parameter(Mandatory = $false)] [string]$KubeDnsSuffix = "svc.cluster.local",
    [parameter(Mandatory = $false)] [string]$KubeConfig = "",
    [parameter(Mandatory = $false)] [string]$KubeVMSwitchName = "k8s-cbr0",
    [ValidateSet('Flannel', 'WinCNI')]
    [parameter(Mandatory = $false)] [string]$KubeCNIComponent = "",
    [ValidateSet('L2Bridge', 'L2Tunnel', 'Overlay')]
    [parameter(Mandatory = $false)] [string]$KubeCNIMode = "",
    [parameter(Mandatory = $false)] [int]$KubeLogLevel = 0,

    [parameter(Mandatory = $false)] [string]$HostName = $env:COMPUTERNAME
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

Function configure-kubernetes-config {
    If ($KubeConfig) {
        $kconfigPath = $KubeConfig

        If (-not (Test-Path $kconfigPath)) {
            $kconfigPath = [Io.path]::Combine($env:ProgramData, "kubernetes", "config")

            [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($KubeConfig)) | Out-File -Encoding ascii -Force -FilePath $kconfigPath
        } Else {
            If (-not (Get-Content $kconfigPath)) {
                Throw "The content of kubeconfig file is empty."
            }
        }

        ## Configure environment variable
        [Environment]::SetEnvironmentVariable("KUBECONFIG", $kconfigPath, [EnvironmentVariableTarget]::User)

        log-info "Setted the environment variable of kubeconfig file on $kconfigPath."
    } Else {
        $kconfigPath = [Environment]::GetEnvironmentVariable("KUBECONFIG", [EnvironmentVariableTarget]::User)

        If (-not $kconfigPath) {
            Throw "The environment variable of kubeconfig file hasn't be setted."
        }

        log-info "The environment variable of kubeconfig file is already setted."
    }
}

Function convert-to-decimal-ip {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Net.IPAddress] $ipAddress
    )

    $i = 3
    $decimalIP = 0

    $ipAddress.GetAddressBytes() | % {
        $decimalIP += $_ * [Math]::Pow(256, $i)
        $i--
    }

    return [UInt32]$decimalIP
}

Function convert-to-dotted-ip {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Uint32] $ipAddress
    )

    $dottedIP = $(for ($i = 3; $i -gt -1; $i--)
    {
        $base = [Math]::Pow(256, $i)
        $remainder = $ipAddress % $base
        ($ipAddress - $remainder) / $base
        $ipAddress = $remainder
    })

    return [String]::Join(".", $dottedIP)
}

Function convert-to-mask-length {
    param(
        [Parameter(Mandatory = $True, Position = 0)]
        [Net.IPAddress] $subnetMask
    )

    $bits = "$($subnetMask.GetAddressBytes() | % {
        [Convert]::ToString($_, 2)
    } )" -replace "[\s0]"

    return $bits.Length
}

Function get-hyperv-vswitch {
    $na = Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*"
    if (-not $na) {
      Throw "Failed to find a suitable Hyper-V vSwitch network adapter, check your network settings."
    }

    $ip = (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4 -ErrorAction Stop).IPAddress
    $subnetMask = (Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | ? InterfaceIndex -eq $($na.ifIndex)).IPSubnet[0]
    $subnet = (convert-to-decimal-ip $ip) -band (convert-to-decimal-ip $subnetMask)
    $subnet = convert-to-dotted-ip $subnet
    $subnetCIDR = "$subnet/$(convert-to-mask-length $subnetMask)"
    $gw = (Get-NetRoute -InterfaceAlias $na.ifAlias -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop).NextHop

    return @{
        Name = $na.ifAlias
        IP = $ip
        CIDR = "$ip/32"
        Subnet = @{
            IP = $subnet
            Mask = $subnetMask
            CIDR = $subnetCIDR
        }
        Gateway = $gw
    }
}

Function get-hyperv-vswitch-ip {
    $na = Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*"
    if (-not $na) {
      Throw "Failed to find a suitable Hyper-V vSwitch network adapter, check your network settings."
    }

    return (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4 -ErrorAction Stop).IPAddress
}

Function get-hyperv-vswitch-subnet {
    $na = Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*"
    if (-not $na) {
      Throw "Failed to find a suitable Hyper-V vSwitch network adapter, check your network settings."
    }

    $ip = (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4 -ErrorAction Stop).IPAddress
    $subnetMask = (Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | ? InterfaceIndex -eq $($na.ifIndex)).IPSubnet[0]
    $subnet = (convert-to-decimal-ip $ip) -band (convert-to-decimal-ip $subnetMask)
    $subnet = convert-to-dotted-ip $subnet
    
    return "$subnet/$(convert-to-mask-length $subnetMask)"
}

Function get-hyperv-vswitch-gateway {
    $na = Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*"
    if (-not $na) {
      Throw "Failed to find a suitable Hyper-V vSwitch network adapter, check your network settings."
    }

    return (Get-NetRoute -InterfaceAlias $na.ifAlias -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop).NextHop
}

Function configure-kubernetes-cni {
    If ($KubeCNIComponent) {
        mkdir -p $env:ProgramFiles\kubernetes\cni -ErrorAction Ignore | Out-Null
        mkdir -p $env:ProgramData\kubernetes\cni -ErrorAction Ignore | Out-Null

        $hnspsmPath = [Io.path]::Combine($env:ProgramFiles, "kubernetes", "hns.psm1")
        If (-not (Test-Path $hnspsmPath)) {
            log-debug "Downloading hns.psm1."

            download -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1" -DestinationPath $hnspsmPath
        }

        Import-Module $env:ProgramFiles\kubernetes\hns.psm1 -Verbose:$false -WarningAction Ignore -ErrorAction Stop

        If ($KubeCNIComponent -eq "WinCNI") {
            log-debug "Using WinCNI."

            ## download WinCNIRoutesWatcher.ps1
            $wincniRouterWathcerPath = [Io.path]::Combine($env:ProgramFiles, "kubernetes", "WinCNIRoutesWatcher.ps1")
            If (-not (Test-Path $wincniRouterWathcerPath)) {
                log-debug "Downloading WinCNIRoutesWatcher.ps1"

                download -Url "https://raw.githubusercontent.com/thxCode/gowinrm/master/test/manual/kubernetes/WinCNIRoutesWatcher.ps1" -DestinationPath $wincniRouterWathcerPath
            }

            ## download wincin.exe
            $wincinPath = [Io.path]::Combine($env:ProgramFiles, "kubernetes", "cni", "wincni.exe")
            If (-not (Test-Path $wincinPath)) {
                log-debug "Donwloading wincin.exe."

                download -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/cni/wincni.exe" -DestinationPath $wincinPath
            }

            ## only allow L2Bridge mode
            $KubeCNIMode = "L2Bridge"
            $kconfigPath = [Environment]::GetEnvironmentVariable("KUBECONFIG", [EnvironmentVariableTarget]::User)

            log-debug "Getting the Pod CIDR of this Kubernetes node."

            $hostname = $HostName.ToLower()
            ## get pod CIDR
            pushd $env:ProgramFiles\kubernetes\node\bin
            $podCIDR = (.\kubectl.exe --kubeconfig=$kconfigPath get nodes/$hostname -o custom-columns=podCIDR:.spec.podCIDR --no-headers)
            popd

            if (-not $podCIDR) {
                ## register this host to get the pod CIDR
                If ($KubeContainerization) {
                     Throw "Kubernetes node components are not currently supported."
                } Else {
                    pushd $env:ProgramFiles\kubernetes\node\bin
                    $process = Start-Process -PassThru -FilePath "kubelet.exe" -ArgumentList "--v=$KubeLogLevel", "--hostname-override=$HostName", "--pod-infra-container-image=kubeletwin/pause", "--resolv-conf=`"`"", "--allow-privileged=true", "--enable-debugging-handlers", "--cluster-dns=$KubeDnsServiceIP", "--cluster-domain=$clusterDomain", "--kubeconfig=$kconfigPath" -ErrorAction Stop

                    while (-not $podCIDR) {
                        log-debug "Waiting for get the pod CIDR of this Kubernetes node."

                        Start-Sleep -s 2
                        
                        $podCIDR = (.\kubectl.exe --kubeconfig=$kconfigPath get nodes/$hostname -o custom-columns=podCIDR:.spec.podCIDR --no-headers)
                    }

                    Stop-Process -Id $process.Id -ErrorAction Stop | Out-Null
                    popd
                }
            }
            
            log-info "Got the Pod CIDR of this Kubernetes node."

            ## create new HNS network
            $hnsNetworkCreateFlag = $true
            $hnsEndpointCreateFlag = $true
            $hnsNetworkName = $KubeVMSwitchName.ToLower()
            $hnsEndpointName = $KubeVMSwitchName.ToLower() + "-" + $KubeCNIMode.ToLower()
            $podGW = $podCIDR.Substring(0,$podCIDR.LastIndexOf(".")) + ".1"
            $podEndpointGW = $podCIDR.Substring(0,$podCIDR.LastIndexOf(".")) + ".2"

            $hnsNetwork = Get-HNSNetwork | ? Name -EQ $hnsNetworkName
            If ($hnsNetwork) {
                If (($hnsNetwork.Subnets.AddressPrefix -ne $podCIDR) -or ($hnsNetwork.Subnets.GatewayAddress -ne $podGW)){
                    log-debug "Cleaning up the early HNS network."

                    docker ps -q | ForEach-Object {docker stop $_ | Out-Null}
                    Remove-HNSNetwork $hnsNetwork
                    Start-Sleep -s 10
                } Else {
                    $hnsNetworkCreateFlag = $false
                }
            } 
            
            If ($hnsNetworkCreateFlag) {
                log-debug "Creating a new HNS network."

                $hnsNetwork = New-HNSNetwork -Type $KubeCNIMode -AddressPrefix $podCIDR -Gateway $podGW -Name $hnsNetworkName -Verbose:$false
                Start-Sleep -s 2
                
                log-info "Creatted a new HNS network."
            } Else {
                log-info "The HNS network is already on using."

                $hnsEndpoint = Get-HnsEndpoint | Where-Object {($_.VirtualNetworkName -eq $hnsNetworkName) -and ($_.OriginalGatewayAddress -eq "0.0.0.0" ) -and ($_.IPAddress -eq $podEndpointGW)}
                If ($hnsEndpoint) {
                    $hnsEndpointCreateFlag = $false
                    $hnsEndpointName = $hnsEndpoint.Name
                }
            }

            $vnicName = "vEthernet ($hnsEndpointName)"
            If ($hnsEndpointCreateFlag) {
                log-debug "Creating a new HNS endpoint."
                
                $hnsEndpoint = New-HnsEndpoint -NetworkId $hnsNetwork.ID -Name $hnsEndpointName -IPAddress $podEndpointGW -Gateway "0.0.0.0" -Verbose:$false
                Start-Sleep -s 2

                Attach-HnsHostEndpoint -EndpointID $hnsEndpoint.ID -CompartmentID 1
                Set-NetIPInterface -InterfaceAlias $vnicName -AddressFamily IPv4 -Dhcp Enabled
                Start-Sleep -s 10

                log-debug "Creatted a new HNS endpoint."
            } Else {
                log-info "The HNS endpoint is already on using."
            }

            log-debug "Generating the CNI config."

            $vswitch = get-hyperv-vswitch
            $cniConfig = @{
                cniVersion = "0.2.0"
                name = $hnsNetworkName
                type = "wincni.exe"
                master =  "Ethernet"
                capabilities = @{
                    portMappings = $true
                }
                ipam = @{
                    environment = "azure"
                    subnet = $podCIDR
                    routes = @(
                        @{
                            GW = $podGW
                        }
                    )
                }
                dns = @{
                    Nameservers = @($KubeDnsServiceIP)
                    Search = @($KubeDnsSuffix)
                }
                AdditionalArgs = @(
                    @{
                        Name = "EndpointPolicy"
                        Value = @{
                            Type = "OutBoundNAT"
                            ExceptionList = @(
                                $KubeClusterCIDR
                                $KubeServiceCIDR
                                $vswitch.Subnet.CIDR
                            )
                        }
                    }
                    @{
                        Name = "EndpointPolicy"
                        Value = @{
                            Type = "ROUTE"
                            NeedEncap = $true
                            DestinationPrefix = $KubeServiceCIDR
                        }
                    }
                    @{
                        Name = "EndpointPolicy"
                        Value = @{
                            Type = "ROUTE"
                            NeedEncap = $true
                            DestinationPrefix = $vswitch.CIDR
                        }
                    }
                )
            }
            $cniConfig | ConvertTo-Json -Compress -Depth 32 | Out-File -Encoding ascii -Force -FilePath "$env:ProgramData\kubernetes\cni\cni.conf"

            log-info "Generated the CNI config."

            log-debug "Adding Routes."

            ## add routes to all remote Pods
            $psWatcher = Start-Process -PassThru -FilePath "powershell" -WorkingDirectory "$env:ProgramFiles\kubernetes" -ArgumentList "-File WinCNIRoutesWatcher.ps1 -LogLevel 0 -VNICName `"$vnicName`" -HyperVSwitchNICName `"$($vswitch.Name)`"" -ErrorAction Stop
            $psWatchers = [Environment]::GetEnvironmentVariable("_PS_WATCHERS", [EnvironmentVariableTarget]::User)
            If ($psWatchers) {
                $psWatchers = $psWatcher.Id + "," + $psWatchers
            } Else {
                $psWatchers = $psWatcher.Id
            }
            [Environment]::SetEnvironmentVariable("_PS_WATCHERS", $psWatchers, [EnvironmentVariableTarget]::User)

            ## add routes to Pods
            $podsRoute = Get-NetRoute -DestinationPrefix $podCIDR -InterfaceAlias $vswitch.Name -ErrorAction Ignore
            If (-not $podsRoute) {
                $podsRoute | Remove-NetRoute -Confirm:$false -ErrorAction Ignore
            }
            New-NetRoute -DestinationPrefix $podCIDR -NextHop 0.0.0.0  -InterfaceAlias $vswitch.Name -Verbose:$false -ErrorAction Ignore | Out-Null

            ## add routes to Kubernetes master
            $kubeMasterRoute = Get-NetRoute -DestinationPrefix "$KubeMasterIP/32" -InterfaceAlias $vswitch.Name -ErrorAction Ignore
            If (-not $kubeMasterRoute) {
                $kubeMasterRoute | Remove-NetRoute -Confirm:$false -ErrorAction Ignore
            }
            New-NetRoute -DestinationPrefix "$KubeMasterIP/32" -NextHop $vswitch.Gateway  -InterfaceAlias $vswitch.Name -Verbose:$false -ErrorAction Ignore | Out-Null

            log-info "Added Routes."

            $hnsPolicyList = Get-HnsPolicyList
            If (-not $hnsPolicyList) {
                log-debug "Cleaning up HNS policy list for run kube-proxy."
                $hnsPolicyList | Remove-HnsPolicyList
                log-debug "Cleaned up HNS policy list for run kube-proxy."
            }

            log-info "Used WinCNI."
        } ElseIf ($KubeCNIComponent -eq "Flannel") {
            Throw "The Flannel CNI component for Windows Server isn't ready."
        } Else {
            Throw "Unknown CNI component."
        }
    }
}

Function start-kubelet {
    log-debug "Starting kubelet."

    If ($KubeContainerization) {
        Throw "Kubernetes node components are not currently supported."
    } Else {
        $process = Get-Process -Name "kubelet" -ErrorAction Ignore
        If (-not $process) {
            $kconfigPath = [Environment]::GetEnvironmentVariable("KUBECONFIG", [EnvironmentVariableTarget]::User)

            $clusterDomain = $KubeDnsSuffix.Substring($KubeDnsSuffix.IndexOf(".")+1)

            Start-Process -FilePath "kubelet.exe" -WorkingDirectory "$env:ProgramFiles\kubernetes\node\bin" -ArgumentList "--v=$KubeLogLevel", "--hostname-override=$HostName", "--pod-infra-container-image=kubeletwin/pause", "--resolv-conf=`"`"", "--allow-privileged=true", "--enable-debugging-handlers", "--cluster-dns=$KubeDnsServiceIP", "--cluster-domain=$clusterDomain", "--kubeconfig=`"$kconfigPath`"", "--hairpin-mode=promiscuous-bridge", "--image-pull-progress-deadline=20m", "--cgroups-per-qos=false", "--enforce-node-allocatable=`"`"", "--network-plugin=cni", "--cni-bin-dir=`"$env:ProgramFiles\kubernetes\cni`"", "--cni-conf-dir=`"$env:ProgramData\kubernetes\cni`"" -ErrorAction Stop

            log-info "Started kubelet."
        } Else {
            log-warn "kubelet is already running."
        }
    }
}

Function stop-kubelet {
    log-debug "Stopping kubelet."

    $process = Get-Process -Name "kubelet" -ErrorAction Ignore
    If ($process) {
        $process | Stop-Process | Out-Null
        log-warn "Stopped kubelet."
    } Else {
        log-info "There isn't kubelet running."
    }
}

Function start-kube-proxy {
    log-debug "Starting kube-proxy."

    If ($KubeContainerization) {
        Throw "Kubernetes node components are not currently supported."
    } Else {
        $process = Get-Process -Name "kube-proxy" -ErrorAction Ignore
        If (-not $process) {
            [Environment]::SetEnvironmentVariable("KUBE_NETWORK", $KubeVMSwitchName.ToLower(), [EnvironmentVariableTarget]::Process)

            $kconfigPath = [Environment]::GetEnvironmentVariable("KUBECONFIG", [EnvironmentVariableTarget]::User)

            Start-Process -FilePath "kube-proxy.exe" -WorkingDirectory "$env:ProgramFiles\kubernetes\node\bin" -ArgumentList "--v=$KubeLogLevel", "--hostname-override=$HostName", "--proxy-mode=kernelspace", "--kubeconfig=$kconfigPath" -ErrorAction Stop | Out-Null
            
            log-info "Started kube-proxy."
        } Else{
            log-warn "kube-proxy is already running."
        }
    }
}

Function stop-kube-proxy {
    log-debug "Stopping kube-proxy."

    $process = Get-Process -Name "kube-proxy" -ErrorAction Ignore
    If ($process) {
        $process | Stop-Process | Out-Null
        log-warn "Stopped kube-proxy."
    } Else {
        log-info "There isn't kube-proxy running."
    }
}

Function build-kubernetes-sandbox-images {
    $hostVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\')
    $hostReleaseId = $hostVersion.ReleaseId

    If (-not (docker images "microsoft/nanoserver:$hostReleaseId" -q)) {
        log-debug "Pulling microsoft/nanoserver:$hostReleaseId ."

        docker pull "microsoft/nanoserver:$hostReleaseId"
        docker tag "microsoft/nanoserver:$hostReleaseId" microsoft/nanoserver:latest

        log-info "Pulled microsoft/nanoserver:$hostReleaseId ."
    }

    If (-not (docker images "microsoft/nanoserver:latest" -q)) {
        docker tag "microsoft/nanoserver:$hostReleaseId" microsoft/nanoserver:latest
    }

    If (-not (docker images "kubeletwin/pause:latest" -q)) {
        $sandboxDockerfilePath = [Io.path]::Combine($env:ProgramFiles, "kubernetes", "Dockerfile")
        If (-not (Test-Path $sandboxDockerfilePath)) {
            log-debug "Downloading sand box Dockerfile ."

            download -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/Dockerfile" -DestinationPath $sandboxDockerfilePath
        }

        log-debug "Building kubeletwin/pause ."
        pushd $env:ProgramFiles\kubernetes
        docker build -t kubeletwin/pause .
        popd
        log-info "Built kubeletwin/pause ."
    }

}

################ Main ################ 

Trap {
    log-err $_
    popd
    Exit 1
}
$ErrorActionPreference = "Stop"

detect-requirements

If ($Reverse) {

    ## stop watchers
    $psWatchers = [Environment]::GetEnvironmentVariable("_PS_WATCHERS", [EnvironmentVariableTarget]::User)
    If ($psWatchers) {
        $psWatcherArr = $psWatchers.Split(",")

        $psWatcherArr | foreach {
            $id = [int]$_
            $process = Get-Process -Id $id -ErrorAction Ignore
            If ($process) {
                $process | Stop-Process | Out-Null
            }
        }

        [Environment]::SetEnvironmentVariable("_PS_WATCHERS", "", [EnvironmentVariableTarget]::User)
    }

    stop-kubelet

    stop-kube-proxy

    log-debug "Purging all Docker containers."

    docker ps -q | ForEach-Object {docker rm -f $_ | Out-Null}
    # docker system prune --volumes -f | Out-Null

    log-warn "Purged all Docker containers."

    log-info "Reversing configuration has been completed."

} Else {
    
    build-kubernetes-sandbox-images

    configure-kubernetes-config

    configure-kubernetes-cni

    start-kubelet

    start-kube-proxy

    log-info "Configuration has been completed."

}
