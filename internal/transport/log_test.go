package transport

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-logr/logr"
	"github.com/tj/assert"
)

func TestLog(t *testing.T) {
	okMock := NewMock(&http.Response{
		StatusCode: 200,
	}, nil)

	logger := NewLogger(logr.Discard(), okMock)
	res, err := logger.RoundTrip(&http.Request{
		URL: &url.URL{},
	})
	assert.Equal(t, 200, res.StatusCode)
	assert.NoError(t, err)

	errMock := NewMock(&http.Response{
		StatusCode: 500,
	}, errors.New("random error"))

	logger = NewLogger(logr.Discard(), errMock)
	res, err = logger.RoundTrip(&http.Request{
		URL: &url.URL{},
	})
	assert.Equal(t, 500, res.StatusCode)
	assert.Error(t, err)
}
