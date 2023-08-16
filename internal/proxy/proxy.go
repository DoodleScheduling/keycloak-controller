package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	infrav1beta1 "github.com/DoodleScheduling/k8skeycloak-controller/api/v1beta1"
)

type proxy struct {
	logger         logr.Logger
	realm          infrav1beta1.KeycloakRealm
	failedRequests chan infrav1beta1.RequestStatus
	scheme         string
	host           string
	path           string
	client         *http.Client
}

func New(realm infrav1beta1.KeycloakRealm, logger logr.Logger, failedRequests chan infrav1beta1.RequestStatus) (net.Listener, error) {
	target, err := url.Parse(realm.Spec.Address)
	if err != nil {
		return nil, err
	}

	proxy := proxy{
		logger:         logger,
		realm:          realm,
		failedRequests: failedRequests,
		scheme:         target.Scheme,
		host:           target.Host,
		path:           target.Path,
		client: &http.Client{
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
	}

	// dynamically select available tcp port
	socket, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	go func() {
		_ = http.Serve(socket, otelhttp.NewHandler(&proxy, "k8skeycloak-controller"))
	}()

	return socket, nil
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(context.TODO())
	clone.URL.Scheme = p.scheme
	clone.URL.Host = p.host
	clone.URL.Path = fmt.Sprintf("%s%s", p.path, r.URL.Path)
	clone.RequestURI = ""

	defer clone.Body.Close()
	var reqBuf bytes.Buffer
	teeRequest := io.TeeReader(clone.Body, &reqBuf)
	clone.Body = io.NopCloser(teeRequest)

	cxt := r.Context()
	span := oteltrace.SpanFromContext(cxt)
	span.SetAttributes(attribute.String("realm", p.realm.Name), attribute.String("namespace", p.realm.Namespace))

	p.logger.V(2).Info("http request sent", "uri", r.URL.String(), "method", r.Method, "body", reqBuf.String())

	res, err := p.client.Do(clone)
	if err != nil {
		p.failedRequests <- infrav1beta1.RequestStatus{
			Verb:  clone.Method,
			URL:   clone.URL.String(),
			Error: err.Error(),
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
	_, _ = io.Copy(w, tee)

	p.logger.V(1).Info("http request", "uri", r.URL.String(), "method", r.Method, "status", res.StatusCode)
	p.logger.V(2).Info("http response received", "uri", r.URL.String(), "method", r.Method, "body", respBuf.String())

	if res.StatusCode >= 400 {
		p.failedRequests <- infrav1beta1.RequestStatus{
			Verb:         clone.Method,
			URL:          clone.URL.String(),
			ResponseCode: res.StatusCode,
			ResponseBody: respBuf.String(),
		}
	}

	res.Body.Close()
}
