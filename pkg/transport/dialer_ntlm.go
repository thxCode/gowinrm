package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	ntlm "github.com/Azure/go-ntlmssp"
)

// Windows Challenge/Response (NTLM) is the authentication protocol used on networks that include systems running the Windows operating system and on stand-alone systems.
// Take more from https://msdn.microsoft.com/en-us/library/windows/desktop/aa378749(v=vs.85).aspx
type NTLM struct {
	SSP
	User     string
	Password string
}

func (ssp *NTLM) getTransport() http.RoundTripper {
	return &ntlm.Negotiator{
		RoundTripper: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ResponseHeaderTimeout: ssp.TransportResponseHeaderTime,
			IdleConnTimeout:       ssp.TransportIdleConnTimeout,
			TLSHandshakeTimeout:   ssp.TransportTLSHandshakeTimeout,
		},
	}
}

func (ssp *NTLM) wrapHttpRequest(httpReq *http.Request) *http.Request {
	httpReq.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	httpReq.Header.Set("User-Agent", "GoWinRM NTLM SSP")
	httpReq.SetBasicAuth(ssp.User, ssp.Password)

	return httpReq
}

func (ssp *NTLM) Dial(requestTimeout time.Duration, requestMsg []byte) ([]byte, error) {
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
