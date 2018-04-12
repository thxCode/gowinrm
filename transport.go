package gowinrm

import (
	"crypto/tls"
	"net/http"
	"unsafe"

	"github.com/Azure/go-ntlmssp"
	"github.com/thxcode/gowinrm/pkg/transport"
)

func ChallengeHttpRequestWrapperFactory(username, password string) transport.HttpRequestWrapper {
	return func(httpReq *http.Request) *http.Request {
		httpReq.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		httpReq.Header.Set("User-Agent", "GoWinRM SSP")
		httpReq.SetBasicAuth(username, password)

		return httpReq
	}
}

func AuthHttpRequestWrapperFactory() transport.HttpRequestWrapper {
	return func(httpReq *http.Request) *http.Request {
		httpReq.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		httpReq.Header.Set("User-Agent", "GoWinRM SSP")
		httpReq.Header.Set("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual")

		return httpReq
	}
}

// Create a Basic Security Support Provider
func NewBasicSSP(username, password string, host string, useTLS bool, security *Security) *transport.SSPImpl {
	if security.HasError() {
		panic(security.err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: (*tls.Config)(unsafe.Pointer(security)),
		},
	}

	return &transport.SSPImpl{
		UseTLS:          useTLS,
		Host:            host,
		WrapHttpRequest: ChallengeHttpRequestWrapperFactory(username, password),
		HttpClient:      httpClient,
	}
}

// Create a NTLM Security Support Provider
func NewNtlmSSP(username, password string, host string, security *Security) *transport.SSPImpl {
	if security.HasError() {
		panic(security.err)
	}

	httpClient := &http.Client{
		Transport: &ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: (*tls.Config)(unsafe.Pointer(security)),
			},
		},
	}

	return &transport.SSPImpl{
		UseTLS:          true,
		Host:            host,
		WrapHttpRequest: ChallengeHttpRequestWrapperFactory(username, password),
		HttpClient:      httpClient,
	}
}

// Create a Certificate Security Support Provider
func NewCertificateSSP(host string, security *Security) *transport.SSPImpl {
	if security.HasError() {
		panic(security.err)
	}

	security.Renegotiation = tls.RenegotiateOnceAsClient

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: (*tls.Config)(unsafe.Pointer(security)),
		},
	}

	return &transport.SSPImpl{
		UseTLS:          true,
		Host:            host,
		WrapHttpRequest: AuthHttpRequestWrapperFactory(),
		HttpClient:      httpClient,
	}
}
