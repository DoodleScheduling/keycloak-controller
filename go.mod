module github.com/DoodleScheduling/k8skeycloak-controller

go 1.15

require (
	github.com/go-logr/logr v0.4.0
	github.com/go-logr/zapr v0.4.0 // indirect
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/prometheus/common v0.10.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	golang.org/x/mod v0.4.0 // indirect
	golang.org/x/tools v0.0.0-20210104081019-d8d6ddbec6ee // indirect
	k8s.io/api v0.20.2
	k8s.io/apiextensions-apiserver v0.20.2 // indirect
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.20.2
	sigs.k8s.io/controller-runtime v0.8.0
)
