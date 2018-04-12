package e2e_test

import (
	"io"
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	"github.com/thxcode/gowinrm"

	log "github.com/sirupsen/logrus"
)

var _ = Describe("CertificateSsp", func() {
	var (
		hostname string
	)

	BeforeEach(func() {
		hostname = "192.168.1.52"
	})

	JustBeforeEach(func() {
		log.SetLevel(log.WarnLevel)
	})

	Context("TLS but not check", func() {
		It("powershell call \"ipconfig.exe /all\"", func() {
			defer GinkgoRecover()

			certPem, err := ioutil.ReadFile("winrm-client-thxcode-cert.pem")
			if err != nil {
				panic(err)
			}

			keyPem, err := ioutil.ReadFile("winrm-client-thxcode-key.pem")
			if err != nil {
				panic(err)
			}

			ssp := gowinrm.NewCertificateSSP(hostname, gowinrm.NewSecurity().WithoutVerify().WithClientCert(certPem, keyPem).WithoutSSL())
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

			certPem, err := ioutil.ReadFile("winrm-client-thxcode-cert.pem")
			if err != nil {
				panic(err)
			}

			keyPem, err := ioutil.ReadFile("winrm-client-thxcode-key.pem")
			if err != nil {
				panic(err)
			}

			serverPemCerts, err := ioutil.ReadFile("winrm-server-cert.pem")
			if err != nil {
				panic(err)
			}

			ssp := gowinrm.NewCertificateSSP(hostname, gowinrm.NewSecurity().WithServerCAs(serverPemCerts).WithClientCert(certPem, keyPem))
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
