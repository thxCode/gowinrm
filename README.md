# gowinrm

gowinrm is a Go client for the Windows Remote Management (WinRM) service.

gowinrm learns inspiration from the following library:
- [WinRb/WinRM](https://github.com/WinRb/WinRM)
- [diyan/pywinrm](https://github.com/diyan/pywinrm)
- [masterzen/winrm](https://github.com/masterzen/winrm)


## Requirements

- Go [v1.10](https://github.com/golang/go/releases/tag/go1.10)
- Go Dep [v0.4.1](https://github.com/golang/dep/releases/tag/v0.4.1)
- WinRM [v2.0](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff520073(v=ws.10)#winrm-20), developing with Windows Server 2016(1709)

## Usage

``` go

// create a dialer
dialer := gowinrm.NewBasicDialer(hostname, username, password)

// create a session
session := gowinrm.NewSession(dialer)
defer session.Close()

// create a result command
cmd, err := session.NewResultCommand(gowinrm.Command, "netstat", "-ano")
defer cmd.Close()
if err != nil {
    panic(err)
}

// create stdout and stderr Writer to receive the execution
stdoutReader, stdoutWriter := io.Pipe()
defer stdoutWriter.Close()
stderrReader, stderrWriter := io.Pipe()
defer stderrWriter.Close()

// print stdout
go func() {
    bytes := make([]byte, 1<<20)
    for {
        size, err := stdoutReader.Read(bytes)
        if size != 0 {
            GinkgoWriter.Write(bytes[:size])
        }
        if err != nil {
            if err == io.EOF {
                break
            } else {
                panic(err)
            }
        }
    }
}()

// print stderr
go func() {
    bytes := make([]byte, 1<<20)
    for {
        size, err := stderrReader.Read(bytes)
        if size != 0 {
            GinkgoWriter.Write(bytes[:size])
        }
        if err != nil {
            if err == io.EOF {
                break
            } else {
                panic(err)
            }
        }
    }
}()

cmd.Receive(map[string]io.Writer{
    "stdout": stdoutWriter,
    "stderr": stderrWriter,
})


```

### Transports



### Command & PowerShell



## Testing




## Setup WinRM

See ["Using OverThere to control a Windows Server from Java"](https://frontier.town/2011/12/overthere-control-windows-from-java/) for information about how to setup WinRM

### Install the WinRM feature

```bash
powershell

> Import-Module servermanager
> Add-WindowsFeature WinRm-IIS-Ext
> Enable-PSRemoting -Force

```

### Configure the WinRM

```bash
> Set-WSManInstance WinRM/Config/Service/Auth -ValueSet @{Basic = $true}
> Set-WSManInstance WinRM/Config/Service -ValueSet @{AllowUnencrypted = $true}
> Set-WSManInstance WinRM/Config/WinRS -ValueSet @{MaxMemoryPerShellMB =1024}
> Set-WSManInstance WinRM/Config/Client -ValueSet @{TrustedHosts = "*"}

```

### Configure the Firewall

```bash
> New-NetFirewallRule -Name powershell-remote-tcp -Direction Inbound -DisplayName 'PowerShell Remote Connection TCP' -LocalPort 5985-5996 -Protocol 'TCP'
> New-NetFirewallRule -Name powershell-remote-udp -Direction Inbound -DisplayName 'PowerShell Remote Connection UDP' -LocalPort 5985-5996 -Protocol 'UDP'

```

