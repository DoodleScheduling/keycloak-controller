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
	"fmt"
	"os"
	"time"

	infrav1beta1 "github.com/DoodleScheduling/k8skeycloak-controller/api/v1beta1"
	"github.com/DoodleScheduling/k8skeycloak-controller/internal/controllers"
	"github.com/DoodleScheduling/k8skeycloak-controller/internal/otelsetup"
	"github.com/fluxcd/pkg/runtime/client"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/leaderelection"
	"github.com/fluxcd/pkg/runtime/logger"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	// +kubebuilder:scaffold:imports
)

const controllerName = "k8skeycloak-controller"

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = corev1.AddToScheme(scheme)
	_ = infrav1beta1.AddToScheme(scheme)
	_ = infrav1beta1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

var (
	metricsAddr             string
	healthAddr              string
	concurrent              int
	gracefulShutdownTimeout time.Duration
	clientOptions           client.Options
	kubeConfigOpts          client.KubeConfigOptions
	logOptions              logger.Options
	leaderElectionOptions   leaderelection.Options
	rateLimiterOptions      helper.RateLimiterOptions
	watchOptions            helper.WatchOptions
	otelOptions             otelsetup.Options
)

func main() {
	flag.StringVar(&metricsAddr, "metrics-addr", ":9556",
		"The address the metric endpoint binds to.")
	flag.StringVar(&healthAddr, "health-addr", ":9557",
		"The address the health endpoint binds to.")
	flag.IntVar(&concurrent, "concurrent", 4,
		"The number of concurrent HelmRelease reconciles.")
	flag.DurationVar(&gracefulShutdownTimeout, "graceful-shutdown-timeout", 600*time.Second,
		"The duration given to the reconciler to finish before forcibly stopping.")

	clientOptions.BindFlags(flag.CommandLine)
	logOptions.BindFlags(flag.CommandLine)
	leaderElectionOptions.BindFlags(flag.CommandLine)
	rateLimiterOptions.BindFlags(flag.CommandLine)
	kubeConfigOpts.BindFlags(flag.CommandLine)
	watchOptions.BindFlags(flag.CommandLine)
	otelOptions.BindFlags(flag.CommandLine)

	flag.Parse()
	logger.SetLogger(logger.NewLogger(logOptions))

	leaderElectionId := fmt.Sprintf("%s-%s", controllerName, "leader-election")
	if watchOptions.LabelSelector != "" {
		leaderElectionId = leaderelection.GenerateID(leaderElectionId, watchOptions.LabelSelector)
	}

	watchNamespace := ""
	if !watchOptions.AllNamespaces {
		watchNamespace = os.Getenv("RUNTIME_NAMESPACE")
	}

	watchSelector, err := helper.GetWatchSelector(watchOptions)
	if err != nil {
		setupLog.Error(err, "unable to configure watch label selector for manager")
		os.Exit(1)
	}

	opts := ctrl.Options{
		Scheme:                        scheme,
		MetricsBindAddress:            metricsAddr,
		HealthProbeBindAddress:        healthAddr,
		LeaderElection:                leaderElectionOptions.Enable,
		LeaderElectionReleaseOnCancel: leaderElectionOptions.ReleaseOnCancel,
		LeaseDuration:                 &leaderElectionOptions.LeaseDuration,
		RenewDeadline:                 &leaderElectionOptions.RenewDeadline,
		RetryPeriod:                   &leaderElectionOptions.RetryPeriod,
		GracefulShutdownTimeout:       &gracefulShutdownTimeout,
		Port:                          9443,
		LeaderElectionID:              leaderElectionId,
		Cache: ctrlcache.Options{
			ByObject: map[ctrlclient.Object]ctrlcache.ByObject{
				&infrav1beta1.KeycloakRealm{}:  {Label: watchSelector},
				&infrav1beta1.KeycloakClient{}: {Label: watchSelector},
				&infrav1beta1.KeycloakUser{}:   {Label: watchSelector},
			},
			Namespaces: []string{watchNamespace},
		},
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), opts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Add liveness probe
	err = mgr.AddHealthzCheck("healthz", healthz.Ping)
	if err != nil {
		setupLog.Error(err, "Could not add liveness probe")
		os.Exit(1)
	}

	// Add readiness probe
	err = mgr.AddReadyzCheck("readyz", healthz.Ping)
	if err != nil {
		setupLog.Error(err, "Could not add readiness probe")
		os.Exit(1)
	}

	realmReconciler := &controllers.KeycloakRealmReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("KeycloakRealm"),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("KeycloakRealm"),
	}

	if err = realmReconciler.SetupWithManager(mgr, controllers.KeycloakRealmReconcilerOptions{
		MaxConcurrentReconciles: viper.GetInt("concurrent"),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakRealm")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if otelOptions.Endpoint != "" {
		tp, err := otelsetup.Tracing(context.Background(), otelOptions)
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				setupLog.Error(err, "failed to shutdown trace provider")
			}
		}()

		if err != nil {
			setupLog.Error(err, "failed to setup trace provider")
		}
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
