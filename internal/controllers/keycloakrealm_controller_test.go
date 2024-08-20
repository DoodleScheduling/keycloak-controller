package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/DoodleScheduling/keycloak-controller/api/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
)

func needStatus(reconciledInstance *v1beta1.KeycloakRealm, expectedStatus *v1beta1.KeycloakRealmStatus) bool {
	for _, expectedCondition := range expectedStatus.Conditions {
		var hasCondition bool
		for _, condition := range reconciledInstance.Status.Conditions {
			if expectedCondition.Type == condition.Type {
				hasCondition = true

				if expectedCondition.Status != condition.Status {
					return false
				}
				if expectedCondition.Reason != condition.Reason {
					return false
				}
				if expectedCondition.Message != condition.Message {
					return false
				}
			}
		}

		if !hasCondition {
			return false
		}
	}

	return true
}

var _ = Describe("KeycloakRealm controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 50
	)

	When("reconciling a suspended KeycloakRealm", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should not update the status", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Address: "http://my-keycloak",
					Suspend: true,
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return len(reconciledInstance.Status.Conditions) == 0
			}, timeout, interval).Should(BeTrue())
		})
	})

	When("a simple realm is reconciled", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("making sure there is a reconciler pod")
			pod := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Succeed())

			By("validating the reconciler pod")
			envs := []corev1.EnvVar{
				{
					Name:  "KEYCLOAK_URL",
					Value: "http://my-keycloak",
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
								Name: authSecret.Name,
							},
							Key: "username",
						},
					},
				},
				{
					Name: "KEYCLOAK_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: authSecret.Name,
							},
							Key: "password",
						},
					},
				},
			}

			Expect(pod.Spec.Containers[0].Image).Should(Equal("test:latest-22.0.1"))
			Expect(pod.Spec.Containers[0].Env).Should(Equal(envs))
			Expect(reconciledInstance.Status.SubResourceCatalog).Should(HaveLen(0))

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())
			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","components":null,"requiredActions":null}`, realm.Name)))
		})

		It("transitions into ready once the reconciler pod terminates", func() {
			reconciledInstance := &v1beta1.KeycloakRealm{}
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			Expect(k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)).Should(Succeed())

			By("setting the reconciler pod as done")
			pod := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Succeed())

			pod.Status.ContainerStatuses = []corev1.ContainerStatus{
				{
					Name: "keycloak-config-cli",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 0,
						},
					},
				},
			}

			Expect(k8sClient.Status().Update(ctx, pod)).Should(Succeed())

			By("waiting for the reconciliation")
			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionTrue,
						Reason:  "ReconciliationSucceeded",
						Message: fmt.Sprintf("reconciler %s terminated with code 0", pod.Name),
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus) && reconciledInstance.Status.Reconciler == ""
			}, timeout, interval).Should(BeTrue())

			By("making sure the reconciler pod is gone")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Not(BeNil()))

			Expect(reconciledInstance.Status.Reconciler).Should(Equal(""))

			By("making sure the realm secret is gone")
			var secret *corev1.Secret
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, secret)).Should(Not(BeNil()))
		})
	})
	When("a realm with no version is reconciled", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("making sure there is a reconciler pod")
			pod := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Succeed())

			By("validating the reconciler pod")
			envs := []corev1.EnvVar{
				{
					Name:  "KEYCLOAK_URL",
					Value: "http://my-keycloak",
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
								Name: authSecret.Name,
							},
							Key: "username",
						},
					},
				},
				{
					Name: "KEYCLOAK_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: authSecret.Name,
							},
							Key: "password",
						},
					},
				},
			}

			Expect(pod.Spec.Containers[0].Image).Should(Equal("test:latest-22.0.1"))
			Expect(pod.Spec.Containers[0].Env).Should(Equal(envs))
			Expect(reconciledInstance.Status.SubResourceCatalog).Should(HaveLen(0))
		})
	})

	When("a realm is reconciled with sub resources", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		clientName := fmt.Sprintf("realm-%s", rand.String(5))
		userName := fmt.Sprintf("user-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			client := &v1beta1.KeycloakClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakClientSpec{},
			}
			Expect(k8sClient.Create(ctx, client)).Should(Succeed())

			user := &v1beta1.KeycloakUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakUserSpec{},
			}
			Expect(k8sClient.Create(ctx, user)).Should(Succeed())

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					ResourceSelector: &metav1.LabelSelector{},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			catalog := []v1beta1.ResourceReference{
				{
					Kind:       "KeycloakClient",
					Name:       clientName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
				{
					Kind:       "KeycloakUser",
					Name:       userName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
			}

			Expect(reconciledInstance.Status.SubResourceCatalog).Should(Equal(catalog))

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","users":[{"username":"%s"}],"clients":[{"clientId":"%s"}],"components":null,"requiredActions":null}`, realm.Name, userName, clientName)))
		})
	})

	When("a realm which has no resource selector will not select any sub resources", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		clientName := fmt.Sprintf("realm-%s", rand.String(5))
		userName := fmt.Sprintf("user-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			client := &v1beta1.KeycloakClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakClientSpec{},
			}
			Expect(k8sClient.Create(ctx, client)).Should(Succeed())

			user := &v1beta1.KeycloakUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakUserSpec{},
			}
			Expect(k8sClient.Create(ctx, user)).Should(Succeed())

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",

					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			Expect(reconciledInstance.Status.SubResourceCatalog).Should(HaveLen(0))
		})
	})

	When("a realm is reconciled with sub resources but limits the resources selected", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		clientName := fmt.Sprintf("realm-%s", rand.String(5))
		userName := fmt.Sprintf("user-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			client := &v1beta1.KeycloakClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: "default",
					Labels: map[string]string{
						"selectable": "yes",
					},
				},
				Spec: v1beta1.KeycloakClientSpec{},
			}
			Expect(k8sClient.Create(ctx, client)).Should(Succeed())

			user := &v1beta1.KeycloakUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: "default",
					Labels: map[string]string{
						"selectable": "no",
					},
				},
				Spec: v1beta1.KeycloakUserSpec{},
			}
			Expect(k8sClient.Create(ctx, user)).Should(Succeed())

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					ResourceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"selectable": "yes",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			catalog := []v1beta1.ResourceReference{
				{
					Kind:       "KeycloakClient",
					Name:       clientName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
			}

			Expect(reconciledInstance.Status.SubResourceCatalog).Should(Equal(catalog))

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","clients":[{"clientId":"%s"}],"components":null,"requiredActions":null}`, realm.Name, clientName)))
		})
	})

	When("a realm with auth credentials and custom credential fields is reconciled", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"x-user":     "kc-user",
					"x-password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name:          authSecret.Name,
						UserField:     "x-user",
						PasswordField: "x-password",
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("validating the reconciler pod")
			pod := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Succeed())

			envs := []corev1.EnvVar{
				{
					Name:  "KEYCLOAK_URL",
					Value: "http://my-keycloak",
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
								Name: authSecret.Name,
							},
							Key: "x-user",
						},
					},
				},
				{
					Name: "KEYCLOAK_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: authSecret.Name,
							},
							Key: "x-password",
						},
					},
				},
			}

			Expect(pod.Spec.Containers[0].Env).Should(Equal(envs))
		})
	})

	When("a realm with secret references is reconciled", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should transition into an error state while the secret is not found", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					Realm: v1beta1.KeycloakAPIRealm{
						DisplayName: "${secret:mysecret:x}",
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionFalse,
						Reason:  "ReconciliationFailed",
						Message: `referencing secret was not found: Secret "mysecret" not found`,
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

		})

		It("successfully substitutes a secret if its found", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			substituteSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mysecret",
					Namespace: "default",
				},
				StringData: map[string]string{
					"x": "secret-field",
				},
			}
			Expect(k8sClient.Create(ctx, substituteSecret)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","displayName":"secret-field","components":null,"requiredActions":null}`, realmName)))
		})
	})

	When("a realm is updated while a reconciler pod is running", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		userName := fmt.Sprintf("user-%s", rand.String(5))

		It("recreates the reconciler with a new secret", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					ResourceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"match": "yes",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			beforeUpdateStatus := reconciledInstance.Status

			user := &v1beta1.KeycloakUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: "default",
					Labels: map[string]string{
						"match": "yes",
					},
				},
				Spec: v1beta1.KeycloakUserSpec{},
			}
			Expect(k8sClient.Create(ctx, user)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus) && reconciledInstance.Status.Reconciler != beforeUpdateStatus.Reconciler && reconciledInstance.Status.Reconciler != ""
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			catalog := []v1beta1.ResourceReference{
				{
					Kind:       "KeycloakUser",
					Name:       userName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
			}

			Expect(reconciledInstance.Status.SubResourceCatalog).Should(Equal(catalog))

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","users":[{"username":"%s"}],"components":null,"requiredActions":null}`, realm.Name, userName)))
		})
	})

	When("a realm reconciliation is triggered if a user is changed", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		userName := fmt.Sprintf("user-%s", rand.String(5))

		It("recreates the reconciler with a new secret", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			user := &v1beta1.KeycloakUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: "default",
					Labels: map[string]string{
						"trigger-users": "yes",
					},
				},
				Spec: v1beta1.KeycloakUserSpec{},
			}
			Expect(k8sClient.Create(ctx, user)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					ResourceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"trigger-users": "yes",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","users":[{"username":"%s"}],"components":null,"requiredActions":null}`, realm.Name, userName)))

			beforeUpdateStatus := reconciledInstance.Status

			enabled := true
			user.Spec.User.Enabled = &enabled
			Expect(k8sClient.Update(ctx, user)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus) && reconciledInstance.Status.Reconciler != beforeUpdateStatus.Reconciler && reconciledInstance.Status.Reconciler != ""
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			catalog := []v1beta1.ResourceReference{
				{
					Kind:       "KeycloakUser",
					Name:       userName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
			}

			Expect(reconciledInstance.Status.SubResourceCatalog).Should(Equal(catalog))

			By("validating the realm secret")
			secret = corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","users":[{"username":"%s","enabled":true}],"components":null,"requiredActions":null}`, realm.Name, userName)))
		})
	})

	When("a realm reconciliation is triggered if a client is changed", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		clientName := fmt.Sprintf("client-%s", rand.String(5))

		It("recreates the reconciler with a new secret", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			client := &v1beta1.KeycloakClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: "default",
					Labels: map[string]string{
						"trigger-clients": "yes",
					},
				},
				Spec: v1beta1.KeycloakClientSpec{},
			}
			Expect(k8sClient.Create(ctx, client)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					ResourceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"trigger-clients": "yes",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","clients":[{"clientId":"%s"}],"components":null,"requiredActions":null}`, realm.Name, clientName)))

			beforeUpdateStatus := reconciledInstance.Status

			publicClient := false
			enabled := true
			client.Spec.Client.Enabled = &enabled
			client.Spec.Client.PublicClient = &publicClient
			Expect(k8sClient.Update(ctx, client)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus) && reconciledInstance.Status.Reconciler != beforeUpdateStatus.Reconciler && reconciledInstance.Status.Reconciler != ""
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			catalog := []v1beta1.ResourceReference{
				{
					Kind:       "KeycloakClient",
					Name:       clientName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
			}

			Expect(reconciledInstance.Status.SubResourceCatalog).Should(Equal(catalog))

			By("validating the realm secret")
			secret = corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","clients":[{"clientId":"%s","enabled":true,"publicClient":false}],"components":null,"requiredActions":null}`, realm.Name, clientName)))
		})
	})

	When("a realm with a custom reconciler pod template is reconciled", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					ReconcilerTemplate: &v1beta1.ReconcilerTemplate{
						ObjectMetadata: v1beta1.ObjectMetadata{
							Labels: map[string]string{
								"test": "label",
							},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "keycloak-config-cli",
									Image: "custom-image:1",
									Env: []corev1.EnvVar{
										{
											Name:  "TEST",
											Value: "TEST",
										},
									},
								},
								{
									Name:  "sidecar",
									Image: "sidecar:1",
								},
							},
						},
					},
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("making sure there is a reconciler pod")
			pod := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Succeed())

			By("validating the reconciler pod")
			envs := []corev1.EnvVar{
				{
					Name:  "TEST",
					Value: "TEST",
				},
				{
					Name:  "KEYCLOAK_URL",
					Value: "http://my-keycloak",
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
								Name: authSecret.Name,
							},
							Key: "username",
						},
					},
				},
				{
					Name: "KEYCLOAK_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: authSecret.Name,
							},
							Key: "password",
						},
					},
				},
			}

			Expect(pod.Labels["test"]).Should(Equal("label"))
			Expect(pod.Spec.Containers[1].Name).Should(Equal("sidecar"))
			Expect(pod.Spec.Containers[1].Image).Should(Equal("sidecar:1"))
			Expect(pod.Spec.Containers[0].Image).Should(Equal("custom-image:1"))
			Expect(pod.Spec.Containers[0].Env).Should(Equal(envs))
			Expect(reconciledInstance.Status.SubResourceCatalog).Should(HaveLen(0))
		})

		It("recreates the running reconciler pod if the spec changed", func() {
			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}
			Expect(k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)).Should(BeNil())

			beforeChangeStatus := reconciledInstance.Status
			reconciledInstance.Spec.ReconcilerTemplate.Spec.Containers[1].Image = "new-image:v1"
			Expect(k8sClient.Update(ctx, reconciledInstance)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return beforeChangeStatus.Reconciler != reconciledInstance.Status.Reconciler && reconciledInstance.Status.Reconciler != ""
			}, timeout, interval).Should(BeTrue())

			By("making sure there is a reconciler pod")
			pod := &corev1.Pod{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, pod)
			}, timeout, interval).Should(BeNil())

			Expect(pod.Spec.Containers[1].Image).Should(Equal("new-image:v1"))
		})

		It("recreates the running reconciler pod if the spec annotation is not present", func() {
			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}
			Expect(k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)).Should(BeNil())
			beforeChangeStatus := reconciledInstance.Status

			pod := &corev1.Pod{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      reconciledInstance.Status.Reconciler,
				Namespace: reconciledInstance.Namespace,
			}, pod)).Should(Succeed())
			pod.Annotations = nil
			Expect(k8sClient.Update(ctx, pod)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return beforeChangeStatus.Reconciler != reconciledInstance.Status.Reconciler && reconciledInstance.Status.Reconciler != ""
			}, timeout, interval).Should(BeTrue())
		})
	})

	When("a realm without auth credentials is reconciled", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))

		It("should transition into progressing", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Version: "22.0.1",
					Address: "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: "does-not-exists",
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionFalse,
						Reason:  "ReconciliationFailed",
						Message: `referencing secret was not found: Secret "does-not-exists" not found`,
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())
		})
	})

	When("a realm with an interval > 0 is triggered if a user is changed", func() {
		realmName := fmt.Sprintf("realm-%s", rand.String(5))
		userName := fmt.Sprintf("user-%s", rand.String(5))

		It("recreates the reconciler with a new secret", func() {
			By("creating a new KeycloakRealm")
			ctx := context.Background()

			authSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("auth-%s", rand.String(5)),
					Namespace: "default",
				},
				StringData: map[string]string{
					"username": "kc-user",
					"password": "kc-password",
				},
			}

			Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

			user := &v1beta1.KeycloakUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: "default",
					Labels: map[string]string{
						"trigger-checksum-users": "yes",
					},
				},
				Spec: v1beta1.KeycloakUserSpec{},
			}
			Expect(k8sClient.Create(ctx, user)).Should(Succeed())

			realm := &v1beta1.KeycloakRealm{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realmName,
					Namespace: "default",
				},
				Spec: v1beta1.KeycloakRealmSpec{
					Interval: &metav1.Duration{Duration: time.Second * 100},
					Version:  "22.0.1",
					Address:  "http://my-keycloak",
					AuthSecret: v1beta1.SecretReference{
						Name: authSecret.Name,
					},
					ResourceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"trigger-checksum-users": "yes",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

			By("waiting for the reconciliation")
			instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
			reconciledInstance := &v1beta1.KeycloakRealm{}

			expectedStatus := &v1beta1.KeycloakRealmStatus{
				ObservedGeneration: 1,
				Conditions: []metav1.Condition{
					{
						Type:    v1beta1.ConditionReady,
						Status:  metav1.ConditionUnknown,
						Reason:  "Progressing",
						Message: "Reconciliation in progress",
					},
					{
						Type:   v1beta1.ConditionReconciling,
						Status: metav1.ConditionTrue,
						Reason: "Progressing",
					},
				},
			}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus)
			}, timeout, interval).Should(BeTrue())

			By("validating the realm secret")
			secret := corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","users":[{"username":"%s"}],"components":null,"requiredActions":null}`, realm.Name, userName)))

			beforeUpdateStatus := reconciledInstance.Status

			enabled := true
			user.Spec.User.Enabled = &enabled
			Expect(k8sClient.Update(ctx, user)).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
				if err != nil {
					return false
				}

				return needStatus(reconciledInstance, expectedStatus) && reconciledInstance.Status.Reconciler != beforeUpdateStatus.Reconciler && reconciledInstance.Status.Reconciler != ""
			}, timeout, interval).Should(BeTrue())

			By("making sure the resource catalog is correct")
			catalog := []v1beta1.ResourceReference{
				{
					Kind:       "KeycloakUser",
					Name:       userName,
					APIVersion: v1beta1.GroupVersion.String(),
				},
			}

			Expect(reconciledInstance.Status.SubResourceCatalog).Should(Equal(catalog))

			By("validating the realm secret")
			secret = corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      reconciledInstance.Status.Reconciler,
					Namespace: reconciledInstance.Namespace,
				}, &secret)
			}, timeout, interval).Should(BeNil())

			Expect(string(secret.Data["realm.json"])).Should(Equal(fmt.Sprintf(`{"realm":"%s","users":[{"username":"%s","enabled":true}],"components":null,"requiredActions":null}`, realm.Name, userName)))
		})
	})
	/*
		TODO: this test is flaky as the controller already progresses into another reconcile if the timeout occurs.

			When("a realm reconciler runs into spec.timeout", func() {
				realmName := fmt.Sprintf("realm-%s", rand.String(5))

				It("recreates the reconciler with a new secret", func() {
					By("creating a new KeycloakRealm")
					ctx := context.Background()

					authSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      fmt.Sprintf("auth-%s", rand.String(5)),
							Namespace: "default",
						},
						StringData: map[string]string{
							"username": "kc-user",
							"password": "kc-password",
						},
					}

					Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())

					realm := &v1beta1.KeycloakRealm{
						ObjectMeta: metav1.ObjectMeta{
							Name:      realmName,
							Namespace: "default",
						},
						Spec: v1beta1.KeycloakRealmSpec{
							Interval: &metav1.Duration{Duration: time.Second * 100},
							Timeout:  &metav1.Duration{Duration: time.Second * 100},
							Version:  "22.0.1",
							AuthSecret: v1beta1.SecretReference{
								Name: authSecret.Name,
							},
						},
					}
					Expect(k8sClient.Create(ctx, realm)).Should(Succeed())

					By("waiting for the reconciliation")
					instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
					reconciledInstance := &v1beta1.KeycloakRealm{}

					expectedStatus := &v1beta1.KeycloakRealmStatus{
						ObservedGeneration: 1,
						Conditions: []metav1.Condition{
							{
								Type:    v1beta1.ConditionReady,
								Status:  metav1.ConditionUnknown,
								Reason:  "Progressing",
								Message: "Reconciliation in progress",
							},
							{
								Type:   v1beta1.ConditionReconciling,
								Status: metav1.ConditionTrue,
								Reason: "Progressing",
							},
						},
					}

					Eventually(func() bool {
						err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
						if err != nil {
							return false
						}

						return needStatus(reconciledInstance, expectedStatus)
					}, timeout, interval).Should(BeTrue())

				})

				It("transitions into unready once the reconciler pod reached the timeout", func() {
					reconciledInstance := &v1beta1.KeycloakRealm{}
					instanceLookupKey := types.NamespacedName{Name: realmName, Namespace: "default"}
					Expect(k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)).Should(Succeed())

					By("container shall be running for 500s")
					pod := &corev1.Pod{}
					Expect(k8sClient.Get(ctx, types.NamespacedName{
						Name:      reconciledInstance.Status.Reconciler,
						Namespace: reconciledInstance.Namespace,
					}, pod)).Should(Succeed())

					pod.Status.ContainerStatuses = []corev1.ContainerStatus{
						{
							Name: "keycloak-config-cli",
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{
									StartedAt: metav1.NewTime(time.Now().Add(time.Second * -500)),
								},
							},
						},
					}

					Expect(k8sClient.Status().Update(ctx, pod)).Should(Succeed())

					By("waiting for the reconciliation")
					expectedStatus := &v1beta1.KeycloakRealmStatus{
						ObservedGeneration: 1,
						Conditions: []metav1.Condition{
							{
								Type:    v1beta1.ConditionReady,
								Status:  metav1.ConditionFalse,
								Reason:  "ReconciliationFailed",
								Message: "reconciler timeout reached",
							},
						},
					}

					Eventually(func() bool {
						err := k8sClient.Get(ctx, instanceLookupKey, reconciledInstance)
						if err != nil {
							return false
						}

						return needStatus(reconciledInstance, expectedStatus)
					}, timeout, interval).Should(BeTrue())

					By("making sure the reconciler pod is gone")
					Expect(k8sClient.Get(ctx, types.NamespacedName{
						Name:      reconciledInstance.Status.Reconciler,
						Namespace: reconciledInstance.Namespace,
					}, pod)).Should(Not(BeNil()))

					Expect(reconciledInstance.Status.Reconciler).Should(Equal(""))

					By("making sure the realm secret is gone")
					var secret *corev1.Secret
					Expect(k8sClient.Get(ctx, types.NamespacedName{
						Name:      reconciledInstance.Status.Reconciler,
						Namespace: reconciledInstance.Namespace,
					}, secret)).Should(Not(BeNil()))
				})
			})
	*/
})
