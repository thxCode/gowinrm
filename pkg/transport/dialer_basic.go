package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Basic struct {
	SSP
	User     string
	Password string
}

func (ssp *Basic) getTransport() http.RoundTripper {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: ssp.TransportResponseHeaderTime,
		IdleConnTimeout:       ssp.TransportIdleConnTimeout,
		TLSHandshakeTimeout:   ssp.TransportTLSHandshakeTimeout,
	}
}

func (ssp *Basic) wrapHttpRequest(httpReq *http.Request) *http.Request {
	httpReq.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	httpReq.Header.Set("User-Agent", "GoWinRM Basic SSP")
	httpReq.SetBasicAuth(ssp.User, ssp.Password)

	return httpReq
}

func (ssp *Basic) Dial(requestTimeout time.Duration, requestMsg []byte) ([]byte, error) {
	if ssp == nil {
		return nil, &GoWinRMErr{
			Actual: errors.New("nil point receiver"),
		}
	}

	if ssp.httpClient == nil {
		ssp.httpClient = &http.Client{
			Transport: ssp.getTransport(),
			Timeout:   ssp.ClientTimeout,
		}
	}

	httpReq, err := http.NewRequest("POST", ssp.GetURL(), bytes.NewReader(requestMsg))
	if err != nil {
		return nil, &GoWinRMErr{
			err,
			"cannot dial to" + ssp.GetURL(),
		}
	}

	if ssp.isClosed() {
		return nil, &GoWinRMErr{
			Actual: errors.New("dialer is closed"),
		}
	}

	if requestTimeout != 0 {
		cancelCtx, cancelFn := context.WithTimeout(context.TODO(), requestTimeout)
		ssp.httpRequestCancelFn = cancelFn
		defer func() {
			if ssp.httpRequestCancelFn != nil {
				ssp.httpRequestCancelFn()
				ssp.httpRequestCancelFn = nil
			}
		}()
		httpReq.WithContext(cancelCtx)
	}

	httpResp, err := ssp.httpClient.Do(ssp.wrapHttpRequest(httpReq))
	if err != nil {
		return nil, &GoWinRMErr{
			err,
			fmt.Sprintf("dial failure to %s, %s", ssp.GetURL(), err.Error()),
		}
	}

	return ssp.DealHttpResponse(httpResp)
}

//// Microsoft Digest is a security support provider (SSP) that implements the Digest Access protocol, a lightweight authentication protocol for parties involved in Hypertext Transfer Protocol (HTTP) or Simple Authentication Security Layer (SASL) based communications.
//// Take more from https://msdn.microsoft.com/en-us/library/windows/desktop/aa378745(v=vs.85).aspx
//type Digest struct {
//}
//
//// The Kerberos protocol defines how clients interact with a network authentication service. Clients obtain tickets from the Kerberos Key Distribution Center (KDC), and they present these tickets to servers when connections are established. Kerberos tickets represent the client's network credentials.
//// Take more from https://msdn.microsoft.com/en-us/library/windows/desktop/aa378747(v=vs.85).aspx
//type Kerberos struct {
//}
//
//// The Credential Security Support Provider protocol (CredSSP) is a Security Support Provider that is implemented by using the Security Support Provider Interface (SSPI).
//// Take more from https://msdn.microsoft.com/en-us/library/windows/desktop/bb931352(v=vs.85).aspx
//type CredSSP struct {
//}
