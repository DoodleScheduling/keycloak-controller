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
	fs.StringVar(&o.ServiceName, "otel-service-name", "k8skeycloak-controller", "Opentelemetry service name")
	fs.StringVar(&o.Endpoint, "otel-endpoint", "", "Opentelemetry gRPC endpoint (without protocol)")
	fs.BoolVar(&o.Insecure, "otel-insecure", false, "Opentelemetry gRPC disable tls")
	fs.StringVar(&o.TLSClientKeyPath, "otel-tls-client-key-path", "", "Opentelemetry gRPC mTLS client key path")
	fs.StringVar(&o.TLSClientCertPath, "otel-tls-client-cert-path", "", "Opentelemetry gRPC mTLS client cert path")
	fs.StringVar(&o.TLSRootCAPath, "otel-tls-root-ca-path", "", "Opentelemetry gRPC mTLS root CA path")
}
