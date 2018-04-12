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

	hostname := "192.168.1.37"
	username := "Administrator"
	password := "123qweASD"

	// read server cert.pem
	serverPemCerts, err := ioutil.ReadFile("winrm-cert.pem")
    if err != nil {
        panic(err)
    }

    // create a ssp
    ssp := gowinrm.NewBasicSSP(username, password, hostname, true, gowinrm.NewSecurity().WithServerCAs(serverPemCerts))

	// create a session
	session := gowinrm.NewSession(ssp)
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
				os.Stdout.Write(bytes[:size])
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
				os.Stderr.Write(bytes[:size])
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



## Testing

1. Access Windows host to run the following command:

``` powershell
# from PowerShell
> wget -o ConfigureWinRM.ps1 https://raw.githubusercontent.com/thxCode/gowinrm/master/test/manual/ConfigureWinRM.ps1

> .\ConfigureWinRM.ps1 -LogLevel 0 -NewCertForce -AuthBasic -SkipEncryptedService -HostIP 192.168.1.52 -AuthCertificate -AuthCertificateUser thxcode

```

Now, the WinRM service is enabled, both HTTP and HTTPS can access. At the same time, we enable the basic authentication, certificate authentication and unencrypted service of WinRM.

``` powsershell

> ls
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/27/2018  12:54 AM          28781 ConfigureWinRM.ps1
-a----        4/27/2018  12:55 AM           1234 winrm-client-thxcode-cert.pem
-a----        4/27/2018  12:55 AM           1920 winrm-client-thxcode-key.pem
-a----        4/27/2018  12:55 AM           1238 winrm-server-cert.pem

```

Please overwrite all `*.pem` files in path/to/`gowinrm/test/e2e`.

2. Use [osni/ginkgo](https://github.com/onsi/ginkgo) to test:

``` bash
$ go get -u github.com/onsi/ginkgo/ginkgo
$ go get -u github.com/onsi/gomega/...

$ cd path/to/gowinrm/test/e2e

$ ginkgo -v

```

## Setup WinRM

See ["Using OverThere to control a Windows Server from Java"](https://frontier.town/2011/12/overthere-control-windows-from-java/) for information about how to setup WinRM.

For convenience, we provide a PowerShell script, named `ConfigureWinRM.ps1`, to help you to setup WinRM easily:

``` powershell
> wget -o ConfigureWinRM.ps1 https://raw.githubusercontent.com/thxCode/gowinrm/master/test/manual/ConfigureWinRM.ps1

```

1. Enable WinRM over HTTP and HTTPS with self-signed certificate (includes firewall rules):

``` powershell
> .\ConfigureWinRM.ps1 -LogLevel 0

```

2. Enable WinRM only over HTTP for test usage (includes firewall rules):

``` powershell
> .\ConfigureWinRM.ps1 -LogLevel 0 -SkipSSL -SkipEncryptedService

```

3. Enable WinRM basic authentication. For domain users, it is necessary to use NTLM, Kerberos or CredSSP authentication (Kerberos and NTLM authentication are enabled by default CredSSP isn't):

``` powershell
> .\ConfigureWinRM.ps1 -LogLevel 0 -AuthBasic

```

*[github.com/thxcode/gowinrm](https://github.com/thxcode/gowinrm) isn't supported Kerberos and CredSSP authentication now.*

4. Enable WinRM CredSSP authentication. This allows double hop support so you can authenticate with a network service when running command son the remote host:

``` powershell
> .\ConfigureWinRM.ps1 -LogLevel 0 -AuthBasic:$false -AuthCredSSP

```

