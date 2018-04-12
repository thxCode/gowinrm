package e2e_test

import (
	"io"

	. "github.com/onsi/ginkgo"
	log "github.com/sirupsen/logrus"
	"github.com/thxcode/gowinrm"
)

var _ = Describe("GoWinRM", func() {
	var (
		hostname string
		username string
		password string
		useTLS   bool
	)

	BeforeEach(func() {
		hostname = "192.168.1.48"
		username = "RancherWinRM"
		password = "123qweASD"
		useTLS = false
	})

	JustBeforeEach(func() {
		log.SetLevel(log.WarnLevel)
	})

	Describe("Basic Dialer", func() {
		Context("non TLS", func() {
			It("command call \"netstat -ano\"", func() {
				defer GinkgoRecover()

				dialer := gowinrm.NewBasicDialer(username, password, hostname, useTLS)
				session := gowinrm.NewSession(dialer)
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

			It("powershell call \"ipconfig.exe /all\"", func() {
				defer GinkgoRecover()

				dialer := gowinrm.NewBasicDialer(username, password, hostname, useTLS)
				session := gowinrm.NewSession(dialer)
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

	})

})
