/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	infrav1beta1 "github.com/DoodleScheduling/keycloak-controller/api/v1beta1"
	"github.com/DoodleScheduling/keycloak-controller/internal/otelsetup"
	"github.com/DoodleScheduling/keycloak-controller/internal/proxy"
	"github.com/DoodleScheduling/keycloak-controller/internal/transport"
	"github.com/fluxcd/pkg/runtime/client"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/go-logr/logr"
	flag "github.com/spf13/pflag"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	// +kubebuilder:scaffold:imports
)

var (
	scheme     = runtime.NewScheme()
	kubeClient kclient.Client
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = infrav1beta1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

var (
	logOptions         logger.Options
	otelOptions        otelsetup.Options
	clientOptions      client.Options
	kubeConfigOpts     client.KubeConfigOptions
	rateLimiterOptions helper.RateLimiterOptions
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	clientOptions.BindFlags(flag.CommandLine)
	logOptions.BindFlags(flag.CommandLine)
	rateLimiterOptions.BindFlags(flag.CommandLine)
	kubeConfigOpts.BindFlags(flag.CommandLine)
	otelOptions.BindFlags(flag.CommandLine)

	flag.Parse()
	log := logger.NewLogger(logOptions)
	logger.SetLogger(log)

	otelOptions.Attributes = []attribute.KeyValue{
		attribute.String("realm", os.Getenv("REALM_NAME")),
		attribute.String("namespace", os.Getenv("REALM_NAMESPACE")),
	}

	if otelOptions.Endpoint != "" {
		tp, err := otelsetup.Tracing(context.Background(), otelOptions)
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				log.Error(err, "failed to shutdown trace provider")
			}
		}()

		if err != nil {
			log.Error(err, "failed to setup trace provider")
		}
	}

	ctx, cancel := context.WithCancel(context.TODO())
	config := ctrl.GetConfigOrDie()
	c, err := kclient.New(config, kclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		panic(err)
	}

	kubeClient = c

	var realm infrav1beta1.KeycloakRealm
	if err := c.Get(ctx, types.NamespacedName{
		Name:      os.Getenv("REALM_NAME"),
		Namespace: os.Getenv("REALM_NAMESPACE"),
	}, &realm); err != nil {
		panic(err)
	}

	failedRequests := make(chan proxy.RequestStatus, 5)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		updateFailedRequests(ctx, log, failedRequests, realm)
	}()

	otelhttp.WithSpanOptions()

	httpClient := &http.Client{}
	httpClient.Transport = transport.NewLogger(log.WithName("controllers").WithName("KeycloakRealm"), otelhttp.NewTransport(http.DefaultTransport))

	httpProxy := proxy.New(httpClient, failedRequests)

	srv := &http.Server{Addr: os.Getenv("PROXY_ADDRESS"), Handler: httpProxy}

	go func() {
		defer wg.Done()

		log.Info("proxy listening", "address", os.Getenv("PROXY_ADDRESS"))
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()

	signal := <-signals
	log.Info("received os signal", "signal", signal)
	cancel()
	ctx, cancel = context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	wg.Wait()
}

func updateFailedRequests(ctx context.Context, log logr.Logger, requests chan proxy.RequestStatus, realm infrav1beta1.KeycloakRealm) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case requestStatus := <-requests:
			log.Info("patching", "req", requestStatus)
			if len(realm.Status.LastFailedRequests) >= 10 {
				realm.Status.LastFailedRequests = realm.Status.LastFailedRequests[1:9]
			}

			realm.Status.LastFailedRequests = append(realm.Status.LastFailedRequests, infrav1beta1.RequestStatus{
				URL:          requestStatus.URL,
				Verb:         requestStatus.Verb,
				SentAt:       metav1.Time{Time: requestStatus.SentAt},
				Duration:     metav1.Duration{Duration: requestStatus.Duration},
				ResponseCode: requestStatus.ResponseCode,
				ResponseBody: requestStatus.ResponseBody,
				Error:        requestStatus.Error,
			})

			if err := patchStatus(ctx, log, &realm); err != nil {
				log.Error(err, "failed to update KeycloakRealm")
			}
		}
	}
}

func patchStatus(ctx context.Context, log logr.Logger, realm *infrav1beta1.KeycloakRealm) error {
	key := kclient.ObjectKeyFromObject(realm)
	latest := &infrav1beta1.KeycloakRealm{}
	if err := kubeClient.Get(ctx, key, latest); err != nil {
		return err
	}

	mergeFrom := latest.DeepCopy()
	mergeFrom.ObjectMeta = realm.ObjectMeta
	latest.Status.LastFailedRequests = realm.Status.LastFailedRequests

	log.Info("updated", "req", mergeFrom.Status.LastFailedRequests, "patch", kclient.MergeFrom(mergeFrom))

	return kubeClient.Status().Patch(ctx, latest, kclient.MergeFrom(mergeFrom))
}
