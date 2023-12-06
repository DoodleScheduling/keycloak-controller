package proxy

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

type proxy struct {
	failedRequests chan RequestStatus
	client         *http.Client
}

type RequestStatus struct {
	URL          string
	Verb         string
	SentAt       time.Time
	Duration     time.Duration
	ResponseCode int
	ResponseBody string
	Error        string
}

func New(client *http.Client, failedRequests chan RequestStatus) *proxy {
	return &proxy{
		failedRequests: failedRequests,
		client:         client,
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sentAt := time.Now()
	r.RequestURI = ""
	res, err := p.client.Do(r)

	if err != nil {
		p.failedRequests <- RequestStatus{
			Verb:   r.Method,
			URL:    r.URL.String(),
			Error:  err.Error(),
			SentAt: sentAt,
		}
		return
	}

	var respBuf bytes.Buffer
	tee := io.TeeReader(res.Body, &respBuf)

	for k, v := range res.Header {
		for _, h := range v {
			w.Header().Add(k, h)
		}
	}

	w.WriteHeader(res.StatusCode)
	_, ioErr := io.Copy(w, tee)

	if res.StatusCode >= 400 || ioErr != nil {
		errMsg := ""
		if ioErr != nil {
			errMsg = ioErr.Error()
		}

		p.failedRequests <- RequestStatus{
			Verb:         r.Method,
			URL:          r.URL.String(),
			Error:        errMsg,
			ResponseCode: res.StatusCode,
			ResponseBody: respBuf.String(),
			SentAt:       sentAt,
			Duration:     time.Since(sentAt),
		}
	}

	res.Body.Close()
}
