package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type HttpRequestWrapper func(httpReq *http.Request) *http.Request

// Security Support Provider
type SSP interface {
	io.Closer

	GetRemoteEndpointAddress() string

	Dial(requestTimeout time.Duration, requestMsg []byte) ([]byte, error)
}

// The implementation of Security Support Provider
type SSPImpl struct {
	HttpClient      *http.Client
	UseTLS          bool
	Host            string
	Port            int64
	WrapHttpRequest HttpRequestWrapper
}

func (ssp *SSPImpl) isClosed() bool {
	if ssp == nil {
		return false
	}

	return ssp.HttpClient == nil
}

func (ssp *SSPImpl) Close() error {
	if ssp != nil {
		ssp.HttpClient = nil
	}

	return nil
}

func (ssp *SSPImpl) GetRemoteEndpointAddress() string {
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

func (ssp *SSPImpl) dealHttpResponse(httpResp *http.Response) ([]byte, error) {
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

func (ssp *SSPImpl) Dial(requestTimeout time.Duration, requestMsg []byte) ([]byte, error) {
	if ssp == nil {
		return nil, &GoWinRMErr{
			Actual: errors.New("nil point receiver"),
		}
	}

	endpointAddress := ssp.GetRemoteEndpointAddress()
	httpReq, err := http.NewRequest("POST", endpointAddress, bytes.NewReader(requestMsg))
	if err != nil {
		return nil, &GoWinRMErr{
			err,
			"cannot dial to" + endpointAddress,
		}
	}

	if ssp.isClosed() {
		return nil, &GoWinRMErr{
			Actual: errors.New("ssp is closed"),
		}
	}

	if requestTimeout != 0 {
		cancelCtx, cancelFn := context.WithTimeout(context.TODO(), requestTimeout)
		defer cancelFn()
		httpReq.WithContext(cancelCtx)
	}

	if ssp.WrapHttpRequest != nil {
		httpReq = ssp.WrapHttpRequest(httpReq)
	}

	httpResp, err := ssp.HttpClient.Do(httpReq)
	if err != nil {
		return nil, &GoWinRMErr{
			err,
			fmt.Sprintf("dial failure to %s, %s", endpointAddress, err.Error()),
		}
	}

	return ssp.dealHttpResponse(httpResp)
}
