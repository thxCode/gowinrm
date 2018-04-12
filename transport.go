package gowinrm

import "github.com/thxcode/gowinrm/pkg/transport"

func NewBasicDialer(username, password string, host string, useTLS bool) *transport.Basic {
	return &transport.Basic{
		SSP: transport.SSP{
			Host:   host,
			UseTLS: useTLS,
		},
		User:     username,
		Password: password,
	}
}

func NewNTLMDialer(username, password string, host string, useTLS bool) *transport.NTLM {
	return &transport.NTLM{
		SSP: transport.SSP{
			Host:   host,
			UseTLS: useTLS,
		},
		User:     username,
		Password: password,
	}
}
