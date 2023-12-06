package transport

import "net/http"

type mock struct {
	res *http.Response
	err error
}

func NewMock(res *http.Response, err error) *mock {
	return &mock{
		res: res,
		err: err,
	}
}

func (p *mock) RoundTrip(req *http.Request) (*http.Response, error) {
	return p.res, p.err
}
