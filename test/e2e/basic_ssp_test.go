package e2e_test

import (
	"io"
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	log "github.com/sirupsen/logrus"
	"github.com/thxcode/gowinrm"
)

var _ = Describe("BasicSsp", func() {
	var (
		hostname string
		username string
		password string
	)

	BeforeEach(func() {
		hostname = "192.168.1.52"
		username = "Administrator"
		password = "123qweASD"
	})

	JustBeforeEach(func() {
		log.SetLevel(log.WarnLevel)
	})

	Context("non TLS", func() {
		// Using non TLS, must run "PS> Set-WSManInstance WinRM/Config/Service -ValueSet @{AllowUnencrypted = $true}"
		It("command call \"netstat -ano\"", func() {
			defer GinkgoRecover()

			ssp := gowinrm.NewBasicSSP(username, password, hostname, false, nil)
			session := gowinrm.NewSession(ssp)
			defer session.Close()

			cmd, err := session.NewResultCommand(gowinrm.Command, "netstat", "-ano")
			defer cmd.Close()
			if err != nil {
				panic(err)
			}

			stdoutReader, stdoutWriter := io.Pipe()
			defer stdoutWriter.Close()
			stderrReader, stderrWriter := io.Pipe()
			defer stderrWriter.Close()

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

		})
	})

	Context("TLS but not check", func() {
		It("powershell call \"ipconfig.exe /all\"", func() {
			defer GinkgoRecover()

			ssp := gowinrm.NewBasicSSP(username, password, hostname, true, gowinrm.NewSecurity().WithoutVerify())
			session := gowinrm.NewSession(ssp)
			defer session.Close()

			cmd, err := session.NewResultCommand(gowinrm.PowerShell, "ipconfig.exe", "/all")
			defer cmd.Close()
			if err != nil {
				panic(err)
			}

			stdoutReader, stdoutWriter := io.Pipe()
			defer stdoutWriter.Close()
			stderrReader, stderrWriter := io.Pipe()
			defer stderrWriter.Close()

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

		})
	})

	Context("TLS", func() {
		It("powershell call \"dir c:\\\"", func() {
			defer GinkgoRecover()

			serverPemCerts, err := ioutil.ReadFile("winrm-server-cert.pem")
			if err != nil {
				panic(err)
			}

			ssp := gowinrm.NewBasicSSP(username, password, hostname, true, gowinrm.NewSecurity().WithServerCAs(serverPemCerts))
			session := gowinrm.NewSession(ssp)
			defer session.Close()

			cmd, err := session.NewResultCommand(gowinrm.PowerShell, "dir", "c:\\")
			defer cmd.Close()
			if err != nil {
				panic(err)
			}

			stdoutReader, stdoutWriter := io.Pipe()
			defer stdoutWriter.Close()
			stderrReader, stderrWriter := io.Pipe()
			defer stderrWriter.Close()

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

		})
	})

})
