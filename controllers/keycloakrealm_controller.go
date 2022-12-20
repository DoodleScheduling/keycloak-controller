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

package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	infrav1beta1 "github.com/DoodleScheduling/k8skeycloak-controller/api/v1beta1"
)

// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakrealms,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakrealms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

const (
	secretIndexKey = ".metadata.secret"
)

// KeycloakRealm reconciles a KeycloakRealm object
type KeycloakRealmReconciler struct {
	client.Client
	Log         logr.Logger
	Scheme      *runtime.Scheme
	Recorder    record.EventRecorder
	secretRegex *regexp.Regexp
}

type KeycloakRealmReconcilerOptions struct {
	MaxConcurrentReconciles int
}

// SetupWithManager adding controllers
func (r *KeycloakRealmReconciler) SetupWithManager(mgr ctrl.Manager, opts KeycloakRealmReconcilerOptions) error {
	r.secretRegex = regexp.MustCompile(`\${secret:([^:}]+):([^:}]+)}`)

	// Index the KeycloakRealm by the Secret references they point at
	if err := mgr.GetFieldIndexer().IndexField(context.TODO(), &infrav1beta1.KeycloakRealm{}, secretIndexKey,
		func(o client.Object) []string {
			// The referenced admin secret gets indexed
			realm := o.(*infrav1beta1.KeycloakRealm)
			keys := []string{
				fmt.Sprintf("%s/%s", realm.GetNamespace(), realm.Spec.AuthSecret.Name),
			}

			// As well as an attempt to index all field secret references
			b, err := json.Marshal(realm.Spec.Realm)
			if err != nil {
				//TODO error handling
				return keys
			}

			results := r.secretRegex.FindAllSubmatch(b, -1)
			for _, result := range results {
				if len(result) > 1 {
					keys = append(keys, fmt.Sprintf("%s/%s", realm.GetNamespace(), string(result[1])))
				}
			}

			return keys
		},
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&infrav1beta1.KeycloakRealm{}, builder.WithPredicates(
			predicate.GenerationChangedPredicate{},
		)).
		Watches(
			&source.Kind{Type: &corev1.Secret{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForSecretChange),
		).
		Watches(
			&source.Kind{Type: &infrav1beta1.KeycloakClient{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForKeycloakClientChange),
		).
		Watches(
			&source.Kind{Type: &infrav1beta1.KeycloakUser{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForKeycloakUserChange),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *KeycloakRealmReconciler) requestsForSecretChange(o client.Object) []reconcile.Request {
	sectet, ok := o.(*corev1.Secret)
	if !ok {
		panic(fmt.Sprintf("expected a Secret, got %T", o))
	}

	ctx := context.Background()
	var list infrav1beta1.KeycloakRealmList
	if err := r.List(ctx, &list, client.MatchingFields{
		secretIndexKey: objectKey(sectet).String(),
	}); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for _, realm := range list.Items {
		r.Log.Info("referenced secret from a KeycloakRealm changed detected", "namespace", realm.GetNamespace(), "realm-name", realm.GetName())
		reqs = append(reqs, reconcile.Request{NamespacedName: objectKey(&realm)})
	}

	return reqs
}

func (r *KeycloakRealmReconciler) requestsForKeycloakClientChange(o client.Object) []reconcile.Request {
	client, ok := o.(*infrav1beta1.KeycloakClient)
	if !ok {
		panic(fmt.Sprintf("expected a KeycloakClient, got %T", o))
	}

	ctx := context.Background()
	var list infrav1beta1.KeycloakRealmList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for _, realm := range list.Items {
		if matches(realm.Labels, client.Spec.RealmSelector) {
			r.Log.Info("change of keycloak client referencing realm detected", "namespace", realm.GetNamespace(), "realm-name", realm.GetName(), "client-name", client.GetName())
			reqs = append(reqs, reconcile.Request{NamespacedName: objectKey(&realm)})
		}
	}

	return reqs
}

func (r *KeycloakRealmReconciler) requestsForKeycloakUserChange(o client.Object) []reconcile.Request {
	user, ok := o.(*infrav1beta1.KeycloakUser)
	if !ok {
		panic(fmt.Sprintf("expected a KeycloakUser, got %T", o))
	}

	ctx := context.Background()
	var list infrav1beta1.KeycloakRealmList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for _, realm := range list.Items {
		if matches(realm.Labels, user.Spec.RealmSelector) {
			r.Log.Info("change of keycloak user referencing realm detected", "namespace", realm.GetNamespace(), "realm-name", realm.GetName(), "user-name", user.GetName())
			reqs = append(reqs, reconcile.Request{NamespacedName: objectKey(&realm)})
		}
	}

	return reqs
}

// Reconcile keycloakrealms
func (r *KeycloakRealmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("Namespace", req.Namespace, "Name", req.NamespacedName, "req", req)
	logger.Info("reconciling KeycloakRealm")

	// Fetch the KeycloakRealm instance
	realm := infrav1beta1.KeycloakRealm{}

	err := r.Client.Get(ctx, req.NamespacedName, &realm)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	if realm.Spec.Suspend {
		return ctrl.Result{}, nil
	}

	realm, err = r.reconcile(ctx, realm, logger)
	res := ctrl.Result{}
	realm.Status.ObservedGeneration = realm.GetGeneration()

	if err != nil {
		r.Recorder.Event(&realm, "Normal", "error", err.Error())
		res = ctrl.Result{Requeue: true}
		realm = infrav1beta1.KeycloakRealmNotReady(realm, infrav1beta1.FailedReason, err.Error())
	} else {
		if realm.Spec.Interval != nil {
			res = ctrl.Result{
				RequeueAfter: realm.Spec.Interval.Duration,
			}
		}

		msg := "Realm successfully reconciled"
		r.Recorder.Event(&realm, "Normal", "info", msg)
		realm = infrav1beta1.KeycloakRealmReady(realm, infrav1beta1.SynchronizedReason, msg)
	}

	// Update status after reconciliation.
	if err := r.patchStatus(ctx, &realm); err != nil {
		logger.Error(err, "unable to update status after reconciliation")
		return ctrl.Result{Requeue: true}, err
	}

	return res, err
}

func (r *KeycloakRealmReconciler) locateJARByVersion(version string) (string, error) {
	p := os.Getenv("ASSETS_PATH")
	if p == "" {
		p = "."
	}

	p = fmt.Sprintf("%s/keycloak-config-cli-%s.jar", p, version)

	_, err := os.Stat(p)
	if err == nil {
		return p, nil
	}

	return "", err
}

func (r *KeycloakRealmReconciler) reconcile(ctx context.Context, realm infrav1beta1.KeycloakRealm, logger logr.Logger) (infrav1beta1.KeycloakRealm, error) {
	jar, err := r.locateJARByVersion(realm.Spec.Version)
	if err != nil {
		return realm, err
	}

	var usr, pw string
	if realm.Spec.AuthSecret != nil {
		usr, pw, err = getSecret(ctx, r.Client, realm)
		if err != nil {
			return realm, err
		}
	}

	msg := "reconcile realm progressing"
	r.Recorder.Event(&realm, "Normal", "info", msg)
	realm = infrav1beta1.KeycloakRealmNotReady(realm, infrav1beta1.ProgressingReason, msg)
	if r.patchStatus(ctx, &realm) != nil {
		return realm, err
	}

	realm, err = r.extendRealmWithClients(ctx, realm, logger)
	if err != nil {
		return realm, err
	}

	realm, err = r.extendRealmWithUsers(ctx, realm, logger)
	if err != nil {
		return realm, err
	}

	var cmd []string

	cmd = append(cmd, "-jar")
	cmd = append(cmd, jar)
	cmd = append(cmd, fmt.Sprintf("--keycloak.url=%s", realm.Spec.Address))
	cmd = append(cmd, "--import.files.locations=/dev/stdin")
	logger.Info("CMD OUT", "cmd", cmd)

	if realm.Spec.AuthSecret != nil {
		cmd = append(cmd, fmt.Sprintf("--keycloak.user=%s", usr))
		cmd = append(cmd, fmt.Sprintf("--keycloak.password=%s", pw))
	}

	exec := exec.Command("/usr/bin/java", cmd...)
	stdin, err := exec.StdinPipe()
	if err != nil {
		realm.Status.LastExececutionOutput = ""
		return realm, err
	}

	raw, err := r.substituteSecrets(ctx, realm)

	if err != nil {
		realm.Status.LastExececutionOutput = ""
		return realm, err
	}

	go func() {
		io.WriteString(stdin, raw)
		stdin.Close()
	}()

	out, err := exec.CombinedOutput()
	realm.Status.LastExececutionOutput = string(out)

	if err != nil {
		return realm, err
	}

	return realm, nil
}

func (r *KeycloakRealmReconciler) extendRealmWithClients(ctx context.Context, realm infrav1beta1.KeycloakRealm, logger logr.Logger) (infrav1beta1.KeycloakRealm, error) {
	// Fetch the KeycloakRealm instance
	var clients infrav1beta1.KeycloakClientList
	err := r.Client.List(ctx, &clients)
	if err != nil {
		return realm, err
	}

	for _, client := range clients.Items {
		if matches(realm.Labels, client.Spec.RealmSelector) {
			realm.Spec.Realm.Clients = append(realm.Spec.Realm.Clients, client.Spec.Client)
		}
	}

	return realm, nil
}

func (r *KeycloakRealmReconciler) extendRealmWithUsers(ctx context.Context, realm infrav1beta1.KeycloakRealm, logger logr.Logger) (infrav1beta1.KeycloakRealm, error) {
	// Fetch the KeycloakRealm instance
	var users infrav1beta1.KeycloakUserList
	err := r.Client.List(ctx, &users)
	if err != nil {
		return realm, err
	}

	for _, user := range users.Items {
		if matches(realm.Labels, user.Spec.RealmSelector) {
			realm.Spec.Realm.Users = append(realm.Spec.Realm.Users, &user.Spec.User)
		}
	}

	return realm, nil
}

func matches(labels map[string]string, selector *metav1.LabelSelector) bool {
	if selector == nil {
		return true
	}

	for kS, vS := range selector.MatchLabels {
		var match bool
		for kL, vL := range selector.MatchLabels {
			if kS == kL && vS == vL {
				match = true
			}
		}

		if !match {
			return false
		}
	}

	return true
}

func (r *KeycloakRealmReconciler) substituteSecrets(ctx context.Context, realm infrav1beta1.KeycloakRealm) (string, error) {
	b, err := json.Marshal(realm.Spec.Realm)
	if err != nil {
		return "", err
	}

	var errors []error
	str := r.secretRegex.ReplaceAllStringFunc(string(b), func(m string) string {
		parts := r.secretRegex.FindStringSubmatch(m)
		secret := &corev1.Secret{}
		secretName := types.NamespacedName{
			Namespace: realm.Namespace,
			Name:      parts[1],
		}
		err := r.Client.Get(ctx, secretName, secret)

		if err != nil {
			errors = append(errors, fmt.Errorf("referencing secret was not found: %w", err))
			return parts[0]
		}

		if val, ok := secret.Data[parts[2]]; !ok {
			errors = append(errors, fmt.Errorf("field %s not found in secret %s", parts[2], parts[1]))
			return parts[0]
		} else {
			return string(val)
		}
	})

	if len(errors) > 0 {
		return str, errors[0]
	}

	return str, nil
}

func getSecret(ctx context.Context, c client.Client, realm infrav1beta1.KeycloakRealm) (string, string, error) {
	namespace := realm.Spec.AuthSecret.Namespace
	if namespace == "" {
		namespace = realm.GetNamespace()
	}

	// Fetch referencing root secret
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Namespace: namespace,
		Name:      realm.Spec.AuthSecret.Name,
	}
	err := c.Get(ctx, secretName, secret)

	// Failed to fetch referenced secret, requeue immediately
	if err != nil {
		return "", "", fmt.Errorf("referencing secret was not found: %w", err)
	}

	usr, pw, err := extractCredentials(realm.Spec.AuthSecret, secret)
	if err != nil {
		return usr, pw, fmt.Errorf("credentials field not found in referenced rootSecret: %w", err)
	}

	return usr, pw, err
}

func extractCredentials(credentials *infrav1beta1.SecretReference, secret *corev1.Secret) (string, string, error) {
	var (
		user string
		pw   string
	)

	if val, ok := secret.Data[credentials.UserField]; !ok {
		return "", "", errors.New("defined username field not found in secret")
	} else {
		user = string(val)
	}

	if val, ok := secret.Data[credentials.PasswordField]; !ok {
		return "", "", errors.New("defined password field not found in secret")
	} else {
		pw = string(val)
	}

	return user, pw, nil
}

func (r *KeycloakRealmReconciler) patchStatus(ctx context.Context, realm *infrav1beta1.KeycloakRealm) error {
	key := client.ObjectKeyFromObject(realm)
	latest := &infrav1beta1.KeycloakRealm{}
	if err := r.Client.Get(ctx, key, latest); err != nil {
		return err
	}

	return r.Client.Status().Patch(ctx, realm, client.MergeFrom(latest))
}

// objectKey returns client.ObjectKey for the object.
func objectKey(object metav1.Object) client.ObjectKey {
	return client.ObjectKey{
		Namespace: object.GetNamespace(),
		Name:      object.GetName(),
	}
}
