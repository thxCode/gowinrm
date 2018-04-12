package gowinrm

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/thxcode/gowinrm/pkg/transport"
)

type Security struct {
	tls.Config
	err error
}

func NewSecurity() *Security {
	return &Security{
		Config: tls.Config{},
	}
}

func (s *Security) HasError() bool {
	if s != nil {
		return s.err != nil
	}

	return false
}

func (s *Security) Error() error {
	if s != nil {
		return s.err
	}

	return nil
}

func (s *Security) WithoutVerify() *Security {
	s.InsecureSkipVerify = true
	return s
}

func (s *Security) WithServerCAs(serverCAsPem []byte) *Security {
	serverCAPool := s.RootCAs
	if serverCAPool == nil {
		serverCAPool = x509.NewCertPool()
		s.RootCAs = serverCAPool
	}

	if !serverCAPool.AppendCertsFromPEM(serverCAsPem) {
		s.err = &transport.GoWinRMErr{
			Msg: "cannot load server CAs pem.",
		}
	}

	return s
}

func (s *Security) WithClientCert(clientCertPem []byte, clientKeyPem []byte) *Security {
	clientCA, err := tls.X509KeyPair(clientCertPem, clientKeyPem)
	if err != nil {
		s.err = &transport.GoWinRMErr{
			Actual: err,
			Msg:    "cannot load client cert and key pem .",
		}
	} else {
		s.Certificates = append(s.Certificates, clientCA)
	}

	return s
}

func (s *Security) WithoutSSL() *Security {
	s.MinVersion = tls.VersionTLS10

	return s
}
