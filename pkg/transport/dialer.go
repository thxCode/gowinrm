package transport

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Dialer interface {
	io.Closer

	GetURL() string

	Dial(requestTimeout time.Duration, requestMsg []byte) ([]byte, error)
}

type SSP struct {
	httpClient          *http.Client
	httpRequestCancelFn context.CancelFunc

	// Use TLS or not
	UseTLS bool

	// Host name or ip address
	Host string

	// Port (http:5985, https:5986)
	Port int64

	// Using in http.Client{}
	//
	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, any
	// redirects, and reading the response body. The timer remains
	// running after Get, Head, Post, or Do return and will
	// interrupt reading of the Response.Body. A Timeout of zero means no timeout.
	ClientTimeout time.Duration

	// Using in http.Transport{}
	//
	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	TransportResponseHeaderTime time.Duration

	// Using in http.Transport{}
	//
	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself. Zero means no limit.
	TransportIdleConnTimeout time.Duration

	// Using in http.Transport{}
	//
	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TransportTLSHandshakeTimeout time.Duration
}

func (ssp *SSP) isClosed() bool {
	if ssp == nil {
		return false
	}

	return ssp.httpClient == nil
}

func (ssp *SSP) Close() error {
	if ssp != nil {
		if ssp.httpRequestCancelFn != nil {
			ssp.httpRequestCancelFn()
			ssp.httpRequestCancelFn = nil
		}
		ssp.httpClient = nil
	}

	return nil
}

func (ssp *SSP) GetURL() string {
	if ssp.Port == 0 {
		if ssp.UseTLS {
			ssp.Port = 5986
		} else {
			ssp.Port = 5985
		}
	}

	stringBuilder := &strings.Builder{}

	if ssp.UseTLS {
		stringBuilder.WriteString("https://")
	} else {
		stringBuilder.WriteString("http://")
	}

	stringBuilder.WriteString(ssp.Host)
	stringBuilder.WriteString(":")
	stringBuilder.WriteString(fmt.Sprint(ssp.Port))
	stringBuilder.WriteString("/wsman")

	return stringBuilder.String()
}

func (ssp *SSP) DealHttpResponse(httpResp *http.Response) ([]byte, error) {
	contentType := httpResp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/soap+xml") {
		body, err := ioutil.ReadAll(httpResp.Body)
		defer httpResp.Body.Close()
		if err != nil {
			return nil, &GoWinRMErr{
				Actual: err,
				Msg:    fmt.Sprintf("error while reading request body, http statusCode %d, http status %s", httpResp.StatusCode, httpResp.Status),
			}
		}

		if len(body) == 0 {
			return nil, &GoWinRMErr{
				Actual: fmt.Errorf("empty response body, http statusCode %d, http status %s", httpResp.StatusCode, httpResp.Status),
			}
		}

		return body, nil
	}

	return nil, &GoWinRMErr{
		Actual: fmt.Errorf("wrong response, http statusCode %d, http status %s", httpResp.StatusCode, httpResp.Status),
	}
}
