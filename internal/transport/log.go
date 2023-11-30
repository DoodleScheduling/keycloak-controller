package transport

import (
	"net/http"

	"github.com/go-logr/logr"
)

type log struct {
	logger logr.Logger
	next   http.RoundTripper
}

func NewLogger(logger logr.Logger, next http.RoundTripper) *log {
	return &log{
		logger: logger,
		next:   next,
	}
}

func (p *log) RoundTrip(req *http.Request) (*http.Response, error) {
	p.logger.V(1).Info("http request sent", "method", req.Method, "uri", req.URL.String(), "headers", req.Header)
	res, err := p.next.RoundTrip(req)

	if err != nil {
		p.logger.Error(err, "http request failed", "method", req.Method, "uri", req.URL.String())
	} else {
		p.logger.V(1).Info("http response received", "method", req.Method, "uri", req.URL.String(), "status", res.StatusCode, "headers", res.Header)
	}

	return res, err
}
