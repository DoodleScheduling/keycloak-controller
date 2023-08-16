package otelsetup

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/spf13/pflag"
)

type Options struct {
	ServiceName       string
	Endpoint          string
	Insecure          bool
	TLSVerify         bool
	TLSClientKeyPath  string
	TLSClientCertPath string
	TLSRootCAPath     string
}

// getTls returns a configuration that enables the use of mutual TLS.
func (o *Options) getTLSConfig() (*tls.Config, error) {
	var tlsConfig = tls.Config{}

	if o.TLSClientCertPath != "" && o.TLSClientKeyPath != "" {
		clientAuth, err := tls.LoadX509KeyPair(o.TLSClientCertPath, o.TLSClientKeyPath)
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{clientAuth}
	}

	if o.TLSRootCAPath != "" {
		caCert, err := os.ReadFile(o.TLSRootCAPath)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	return &tlsConfig, nil
}

// BindFlags will parse the given pflag.FlagSet
func (o *Options) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Endpoint, "otel-endpoint", "localhost:4317", "Opentelemetry grpc endpoint")
	fs.BoolVar(&o.Insecure, "otel-insecure", false, "Opentelemetry grpc disable tls")
}
