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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	infrav1beta1 "github.com/DoodleScheduling/keycloak-controller/api/v1beta1"
	"github.com/DoodleScheduling/keycloak-controller/internal/merge"
)

// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakrealms,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keycloak.infra.doodle.com,resources=keycloakrealms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;update;patch;delete;watch;list
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;update;patch;delete;watch;list
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

const (
	secretIndexKey = ".metadata.secret"
)

// KeycloakRealm reconciles a KeycloakRealm object
type KeycloakRealmReconciler struct {
	client.Client
	Log                logr.Logger
	Scheme             *runtime.Scheme
	Recorder           record.EventRecorder
	secretRegex        *regexp.Regexp
	ReconcilerRegistry string
	HTTPClient         *http.Client
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
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForSecretChange),
		).
		Watches(
			&infrav1beta1.KeycloakClient{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForChangeBySelector),
		).
		Watches(
			&infrav1beta1.KeycloakUser{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForChangeBySelector),
		).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &infrav1beta1.KeycloakRealm{}, handler.OnlyControllerOwner()),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *KeycloakRealmReconciler) requestsForSecretChange(ctx context.Context, o client.Object) []reconcile.Request {
	secret, ok := o.(*corev1.Secret)
	if !ok {
		panic(fmt.Sprintf("expected a Secret, got %T", o))
	}

	var list infrav1beta1.KeycloakRealmList
	if err := r.List(ctx, &list, client.MatchingFields{
		secretIndexKey: objectKey(secret).String(),
	}); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for _, realm := range list.Items {
		r.Log.V(1).Info("referenced secret from a KeycloakRealm changed detected", "namespace", realm.GetNamespace(), "realm-name", realm.GetName())
		reqs = append(reqs, reconcile.Request{NamespacedName: objectKey(&realm)})
	}

	return reqs
}

func (r *KeycloakRealmReconciler) requestsForChangeBySelector(ctx context.Context, o client.Object) []reconcile.Request {
	var list infrav1beta1.KeycloakRealmList
	if err := r.List(ctx, &list, client.InNamespace(o.GetNamespace())); err != nil {
		return nil
	}

	var reqs []reconcile.Request
	for _, realm := range list.Items {
		labelSel, err := metav1.LabelSelectorAsSelector(realm.Spec.ResourceSelector)
		if err != nil {
			r.Log.Error(err, "can not select resourceSelector selectors")
			continue
		}

		if labelSel.Matches(labels.Set(o.GetLabels())) {
			r.Log.V(1).Info("referenced resource from a KeycloakRealm changed detected", "namespace", realm.GetNamespace(), "realm-name", realm.GetName())
			reqs = append(reqs, reconcile.Request{NamespacedName: objectKey(&realm)})
		}
	}

	return reqs
}

// Reconcile keycloakrealms
func (r *KeycloakRealmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("namespace", req.Namespace, "name", req.NamespacedName)
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

	logger = r.Log.WithValues("resource-version", realm.ResourceVersion)

	if realm.Spec.Suspend {
		return ctrl.Result{}, nil
	}

	realm, result, reconcileErr := r.reconcile(ctx, realm, logger)
	realm.Status.ObservedGeneration = realm.GetGeneration()
	logger.Info("finished reconciling KeycloakRealm")

	if reconcileErr != nil {
		logger.Error(err, "reconcile error occurred")
		realm = infrav1beta1.KeycloakRealmReady(realm, metav1.ConditionFalse, "ReconciliationFailed", reconcileErr.Error())
		r.Recorder.Event(&realm, "Normal", "error", reconcileErr.Error())
	}

	// Update status after reconciliation.
	if err := r.patchStatus(ctx, &realm, logger); err != nil {
		logger.Error(err, "unable to update status after reconciliation")
		return ctrl.Result{}, err
	}

	return result, reconcileErr
}

func (r *KeycloakRealmReconciler) reconcile(ctx context.Context, realm infrav1beta1.KeycloakRealm, logger logr.Logger) (infrav1beta1.KeycloakRealm, ctrl.Result, error) {
	realm.Status.SubResourceCatalog = []infrav1beta1.ResourceReference{}

	realm, err := r.extendRealmWithClients(ctx, realm)
	if err != nil {
		return realm, ctrl.Result{}, err
	}

	realm, err = r.extendRealmWithUsers(ctx, realm)
	if err != nil {
		return realm, ctrl.Result{}, err
	}

	if realm.Spec.Realm.Realm == "" {
		realm.Spec.Realm.Realm = realm.Name
	}

	raw, err := r.substituteSecrets(ctx, realm)
	if err != nil {
		return realm, ctrl.Result{}, err
	}

	checksumSha := sha256.New()
	checksumSha.Write([]byte(raw))
	checksum := fmt.Sprintf("%x", checksumSha.Sum(nil))

	pod := &corev1.Pod{}
	secret := &corev1.Secret{}

	var secretErr error
	var podErr error
	var needUpdate bool

	cleanup := func() error {
		if secretErr == nil {
			if err := r.Client.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("could not delete realm secret: %w", err)
			}
		}

		if podErr == nil {
			if err := r.Client.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("could not delete reconciler pod: %w", err)
			}
		}

		return nil
	}

	// check for stale reconciler
	if realm.Status.Reconciler != "" {
		secretErr = r.Client.Get(ctx, client.ObjectKey{Name: realm.Status.Reconciler, Namespace: realm.Namespace}, secret)
		podErr = r.Client.Get(ctx, client.ObjectKey{Name: realm.Status.Reconciler, Namespace: realm.Namespace}, pod)

		if current, ok := secret.Data["realm.json"]; ok {
			needUpdate = raw != string(current)
		}

		specVersion, ok := pod.Annotations["keycloak-controller/realm-spec-version"]
		if !needUpdate && podErr == nil && ok {
			needUpdate = specVersion != fmt.Sprintf("%d", realm.Generation)
		}

		specChecksum, ok := pod.Annotations["keycloak-controller/realm-checksum"]
		if !needUpdate && podErr == nil && ok {
			needUpdate = specChecksum != checksum
		}

		if !ok {
			needUpdate = true
		}

		if secretErr != nil && !apierrors.IsNotFound(secretErr) {
			return realm, ctrl.Result{}, secretErr
		}

		if podErr != nil && !apierrors.IsNotFound(podErr) {
			return realm, ctrl.Result{}, podErr
		}
	}

	readyCondition := conditions.Get(&realm, infrav1beta1.ConditionReady)
	progressingCondition := conditions.Get(&realm, infrav1beta1.ConditionReconciling)

	// unlink realm reconciler only if the reconciler pod and the secret is gone
	if apierrors.IsNotFound(podErr) && apierrors.IsNotFound(secretErr) {
		conditions.Delete(&realm, infrav1beta1.ConditionReconciling)

		realm.Status.Reconciler = ""
		realm.Status.LastFailedRequests = nil
		return realm, ctrl.Result{Requeue: true}, nil
	}

	// cleanup reconciler pod if stale
	if needUpdate {
		logger.V(1).Info("realm checksum changed, delete stale reconciler", "pod-name", realm.Status.Reconciler)
		return realm, ctrl.Result{}, cleanup()
	}

	// garbage collect reconciler pod
	if progressingCondition != nil && readyCondition != nil && readyCondition.Status != metav1.ConditionUnknown && podErr == nil && realm.Status.Reconciler != "" {
		logger.V(1).Info("garbage collect reconciler pod", "pod-name", realm.Status.Reconciler)
		return realm, ctrl.Result{}, cleanup()
	}

	// rate limiter
	if readyCondition != nil && readyCondition.Status == metav1.ConditionTrue && (realm.Spec.Interval == nil || time.Since(readyCondition.LastTransitionTime.Time) < realm.Spec.Interval.Duration) && realm.Generation == readyCondition.ObservedGeneration {
		logger.V(1).Info("skip reconciliation, last transition time too recent")

		if realm.Spec.Interval != nil {
			return realm, ctrl.Result{
				RequeueAfter: realm.Spec.Interval.Duration,
			}, nil
		} else {
			return realm, ctrl.Result{}, nil
		}
	}

	// handle reconciler pod state
	if podErr == nil && pod.Name != "" {
		return r.handlerReconcilerState(realm, pod, logger)
	}

	return r.createReconciler(ctx, realm, raw, checksum, logger)
}

func (r *KeycloakRealmReconciler) handlerReconcilerState(realm infrav1beta1.KeycloakRealm, pod *corev1.Pod, logger logr.Logger) (infrav1beta1.KeycloakRealm, ctrl.Result, error) {
	var containerStatus *corev1.ContainerStatus
	for _, container := range pod.Status.ContainerStatuses {
		if container.Name == "keycloak-config-cli" {
			containerStatus = &container
			break
		}
	}

	switch {
	case containerStatus == nil:
		return realm, ctrl.Result{}, nil
	case containerStatus.State.Terminated != nil && containerStatus.State.Terminated.ExitCode == 0:
		logger.Info("reconciler pod succeeded", "pod-name", realm.Status.Reconciler)
		realm = infrav1beta1.KeycloakRealmReady(realm, metav1.ConditionTrue, "ReconciliationSucceeded", fmt.Sprintf("reconciler %s terminated with code 0", realm.Status.Reconciler))
		msg := "Realm successfully reconciled"
		r.Recorder.Event(&realm, "Normal", "info", msg)
		return realm, ctrl.Result{Requeue: true}, nil

	case containerStatus.State.Terminated != nil:
		realm = infrav1beta1.KeycloakRealmReady(realm, metav1.ConditionFalse, "ReconciliationFailed", fmt.Sprintf("reconciler terminated with code %d", containerStatus.State.Terminated.ExitCode))
		return realm, ctrl.Result{Requeue: true}, nil

	case containerStatus.State.Running != nil && realm.Spec.Timeout != nil && time.Since(containerStatus.State.Running.StartedAt.Time) >= realm.Spec.Timeout.Duration:
		conditions.Delete(&realm, infrav1beta1.ConditionReconciling)
		return realm, reconcile.Result{}, errors.New("reconciler timeout reached")
	}

	return realm, ctrl.Result{}, nil
}

func (r *KeycloakRealmReconciler) createReconciler(ctx context.Context, realm infrav1beta1.KeycloakRealm, raw string, checksum string, logger logr.Logger) (infrav1beta1.KeycloakRealm, ctrl.Result, error) {
	r.Recorder.Event(&realm, "Normal", "info", "reconcile realm progressing")
	realm = infrav1beta1.KeycloakRealmReady(realm, metav1.ConditionUnknown, "Progressing", "Reconciliation in progress")
	realm = infrav1beta1.KeycloakRealmReconciling(realm, metav1.ConditionTrue, "Progressing", "")

	controllerOwner := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("keycloakrealm-%s-%s", realm.Name, rand.String(5)),
			Labels: map[string]string{
				"app.kubernetes.io/instance": "realm-reconciler",
				"app.kubernetes.io/name":     "keycloak-controller",
				"keycloak-controller/realm":  realm.Name,
			},
			Namespace: realm.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					Name:       realm.Name,
					APIVersion: realm.APIVersion,
					Kind:       realm.Kind,
					UID:        realm.UID,
					Controller: &controllerOwner,
				},
			},
		},
		StringData: map[string]string{
			"realm.json": raw,
		},
	}

	template := &corev1.Pod{}

	if realm.Spec.ReconcilerTemplate != nil {
		template.ObjectMeta.Labels = realm.Spec.ReconcilerTemplate.Labels
		template.ObjectMeta.Annotations = realm.Spec.ReconcilerTemplate.Annotations
		realm.Spec.ReconcilerTemplate.Spec.DeepCopyInto(&template.Spec)
	}

	template.Name = secret.Name
	template.OwnerReferences = secret.OwnerReferences
	template.Namespace = realm.Namespace
	template.ResourceVersion = ""
	template.UID = ""

	if template.ObjectMeta.Labels == nil {
		template.ObjectMeta.Labels = make(map[string]string)
	}

	template.ObjectMeta.Labels["app.kubernetes.io/instance"] = "realm-reconciler"
	template.ObjectMeta.Labels["app.kubernetes.io/name"] = "keycloak-controller"
	template.ObjectMeta.Labels["keycloak-controller/realm"] = realm.Name

	if template.Annotations == nil {
		template.Annotations = make(map[string]string)
	}

	template.Annotations["keycloak-controller/realm-spec-version"] = fmt.Sprintf("%d", realm.Generation)
	template.Annotations["keycloak-controller/realm-checksum"] = checksum

	usernameField := "username"
	passwordField := "password"

	if realm.Spec.AuthSecret.UserField != "" {
		usernameField = realm.Spec.AuthSecret.UserField
	}

	if realm.Spec.AuthSecret.PasswordField != "" {
		passwordField = realm.Spec.AuthSecret.PasswordField
	}

	tag := fmt.Sprintf("latest-%s", realm.Spec.Version)
	username, password, err := getSecret(ctx, r.Client, realm, usernameField, passwordField)
	if err != nil {
		return realm, ctrl.Result{}, err
	}

	if realm.Spec.Version == "" {
		version, err := r.getKeycloakVersion(ctx, realm, username, password)
		if err != nil {
			return realm, reconcile.Result{}, err
		}

		logger.Info("keycloak version detected", "version", version)
		tag = fmt.Sprintf("latest-%s", version)
	}

	containers := []corev1.Container{
		{
			Name:  "keycloak-config-cli",
			Image: fmt.Sprintf("%s:%s", r.ReconcilerRegistry, tag),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "realm",
					MountPath: "/realm",
					ReadOnly:  true,
				},
			},
			Env: []corev1.EnvVar{
				{
					Name:  "KEYCLOAK_URL",
					Value: realm.Spec.Address,
				},
				{
					Name:  "IMPORT_FILES_LOCATIONS",
					Value: "/realm/realm.json",
				},
				{
					Name: "KEYCLOAK_USER",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: realm.Spec.AuthSecret.Name,
							},
							Key: usernameField,
						},
					},
				},
				{
					Name: "KEYCLOAK_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: realm.Spec.AuthSecret.Name,
							},
							Key: passwordField,
						},
					},
				},
			},
		},
	}

	containers, err = merge.MergePatchContainers(containers, template.Spec.Containers)
	if err != nil {
		return realm, ctrl.Result{}, err
	}

	template.Spec.RestartPolicy = corev1.RestartPolicyNever
	template.Spec.Containers = containers
	template.Spec.Volumes = append(template.Spec.Volumes, corev1.Volume{
		Name: "realm",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: secret.Name,
			},
		},
	})

	// If the status update fails the creation of the reconciler pod is postponed to the next reconciliation run
	realm.Status.Reconciler = template.Name
	realm.Status.LastFailedRequests = nil

	if err := r.patchStatus(ctx, &realm, logger); err != nil {
		return realm, ctrl.Result{}, err
	}

	logger.Info("creating new realm secret", "secret", secret.Name)
	if err := r.Client.Create(ctx, secret); err != nil {
		return realm, ctrl.Result{}, err
	}

	logger.Info("create new reconciler pod", "pod", template.Name, "previous", realm.Status.Reconciler)
	if err := r.Client.Create(ctx, template); err != nil {
		return realm, ctrl.Result{}, err
	}

	if realm.Spec.Timeout != nil {
		return realm, ctrl.Result{
			RequeueAfter: realm.Spec.Timeout.Duration,
		}, nil
	}

	return realm, ctrl.Result{}, err
}

func getSecret(ctx context.Context, c client.Client, realm infrav1beta1.KeycloakRealm, usernameField, passwordField string) (string, string, error) {
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

	usr, pw, err := extractCredentials(secret, usernameField, passwordField)
	if err != nil {
		return usr, pw, fmt.Errorf("credentials field not found in referenced authSecret: %w", err)
	}

	return usr, pw, err
}

func extractCredentials(secret *corev1.Secret, usernameField, passwordField string) (string, string, error) {
	var (
		user string
		pw   string
	)

	if val, ok := secret.Data[usernameField]; !ok {
		return "", "", errors.New("username field not found in secret")
	} else {
		user = string(val)
	}

	if val, ok := secret.Data[passwordField]; !ok {
		return "", "", errors.New("password field not found in secret")
	} else {
		pw = string(val)
	}

	return user, pw, nil
}

func (r *KeycloakRealmReconciler) getKeycloakVersion(ctx context.Context, realm infrav1beta1.KeycloakRealm, username, password string) (string, error) {
	formData := url.Values{
		"username":   {username},
		"password":   {password},
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", realm.Spec.Address), strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("keycloak token request setup failed: %w", err)
	}
	req = req.WithContext(ctx)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak token request failed: %w", err)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("keycloak token read body failed: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 400 || resp.StatusCode == 0 {
		return "", fmt.Errorf("keycloak token request failed with status %d: %s", resp.StatusCode, string(b))
	}

	bearerResponse := struct {
		AccessToken string `json:"access_token"`
	}{}

	if err := json.Unmarshal(b, &bearerResponse); err != nil {
		return "", fmt.Errorf("keycloak token response decode failed: %w", err)
	}

	systemInfoResponse := struct {
		SystemInfo struct {
			Version string `json:"version"`
		} `json:"systemInfo"`
	}{}

	req, err = http.NewRequest("GET", fmt.Sprintf("%s/admin/serverinfo", realm.Spec.Address), nil)
	if err != nil {
		return "", fmt.Errorf("keycloak serverinfo request setup failed: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerResponse.AccessToken))
	resp, err = r.HTTPClient.Do(req)

	if err != nil {
		return "", fmt.Errorf("keycloak serverinfo request failed: %w", err)
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("keycloak serverinfo read body failed: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 400 || resp.StatusCode == 0 {
		return "", fmt.Errorf("keycloak serverinfo request failed with status %d: %s", resp.StatusCode, string(b))
	}

	if err := json.Unmarshal(b, &systemInfoResponse); err != nil {
		return "", fmt.Errorf("keycloak serverinfo response decode failed: %w", err)
	}

	return systemInfoResponse.SystemInfo.Version, nil
}

func (r *KeycloakRealmReconciler) extendRealmWithClients(ctx context.Context, realm infrav1beta1.KeycloakRealm) (infrav1beta1.KeycloakRealm, error) {
	var clients infrav1beta1.KeycloakClientList
	selector, err := metav1.LabelSelectorAsSelector(realm.Spec.ResourceSelector)
	if err != nil {
		return realm, err
	}

	err = r.Client.List(ctx, &clients, client.InNamespace(realm.Namespace), client.MatchingLabelsSelector{Selector: selector})
	if err != nil {
		return realm, err
	}

	for _, client := range clients.Items {
		realm.Status.SubResourceCatalog = append(realm.Status.SubResourceCatalog, infrav1beta1.ResourceReference{
			Kind:       client.Kind,
			Name:       client.Name,
			APIVersion: client.APIVersion,
		})

		if client.Spec.Client.ClientID == "" {
			client.Spec.Client.ClientID = client.Name
		}

		realm.Spec.Realm.Clients = append(realm.Spec.Realm.Clients, client.Spec.Client)
	}

	sort.Slice(realm.Spec.Realm.Clients, func(i, j int) bool {
		return realm.Spec.Realm.Clients[i].ClientID < realm.Spec.Realm.Clients[j].ClientID
	})
	sort.Slice(realm.Status.SubResourceCatalog, func(i, j int) bool {
		return realm.Status.SubResourceCatalog[i].Name < realm.Status.SubResourceCatalog[j].Name
	})

	return realm, nil
}

func (r *KeycloakRealmReconciler) extendRealmWithUsers(ctx context.Context, realm infrav1beta1.KeycloakRealm) (infrav1beta1.KeycloakRealm, error) {
	var users infrav1beta1.KeycloakUserList
	selector, err := metav1.LabelSelectorAsSelector(realm.Spec.ResourceSelector)
	if err != nil {
		return realm, err
	}

	err = r.Client.List(ctx, &users, client.InNamespace(realm.Namespace), client.MatchingLabelsSelector{Selector: selector})
	if err != nil {
		return realm, err
	}

	for _, user := range users.Items {
		realm.Status.SubResourceCatalog = append(realm.Status.SubResourceCatalog, infrav1beta1.ResourceReference{
			Kind:       user.Kind,
			Name:       user.Name,
			APIVersion: user.APIVersion,
		})

		if user.Spec.User.UserName == "" {
			user.Spec.User.UserName = user.Name
		}

		realm.Spec.Realm.Users = append(realm.Spec.Realm.Users, user.Spec.User)
	}

	sort.Slice(realm.Spec.Realm.Users, func(i, j int) bool {
		return realm.Spec.Realm.Users[i].UserName < realm.Spec.Realm.Users[j].UserName
	})
	sort.Slice(realm.Status.SubResourceCatalog, func(i, j int) bool {
		return realm.Status.SubResourceCatalog[i].Name < realm.Status.SubResourceCatalog[j].Name
	})

	return realm, nil
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

func (r *KeycloakRealmReconciler) patchStatus(ctx context.Context, realm *infrav1beta1.KeycloakRealm, logger logr.Logger) error {
	key := client.ObjectKeyFromObject(realm)
	latest := &infrav1beta1.KeycloakRealm{}
	if err := r.Client.Get(ctx, key, latest); err != nil {
		return err
	}

	//	logger.V(1).Info("update .status", "new", realm.Status, "current", latest.Status)

	return r.Client.Status().Patch(ctx, realm, client.MergeFrom(latest))
}

// objectKey returns client.ObjectKey for the object.
func objectKey(object metav1.Object) client.ObjectKey {
	return client.ObjectKey{
		Namespace: object.GetNamespace(),
		Name:      object.GetName(),
	}
}
