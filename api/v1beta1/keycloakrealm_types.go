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

package v1beta1

import (
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeycloakRealmSpec defines the desired state of KeycloakRealm
type KeycloakRealmSpec struct {
	// +required
	Address string `json:"address"`

	// Contains a credentials set of a user with enough permission to manage keycloak
	// +optional
	AuthSecret *SecretReference `json:"authSecret,omitempty"`

	// Interval reconciliation
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`

	// Suspend reconciliation
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Version is the keycloak version
	// +required
	Version string `json:"version"`

	// +required
	Realm extv1.JSON `json:"realm"`
}

// SecretReference is a named reference to a secret which contains user credentials
type SecretReference struct {
	// Name referrs to the name of the secret, must be located whithin the same namespace
	// +required
	Name string `json:"name"`

	// Namespace, by default the same namespace is used.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// +optional
	// +kubebuilder:default:=username
	UserField string `json:"userField"`

	// +optional
	// +kubebuilder:default:=password
	PasswordField string `json:"passwordField"`
}

// KeycloakRealmStatus defines the observed state of KeycloakRealm
type KeycloakRealmStatus struct {
	// Conditions holds the conditions for the VaultBinding.
	// +optional
	Conditions            []metav1.Condition `json:"conditions,omitempty"`
	LastExececutionOutput string             `json:"lastExececutionOutput"`
}

const (
	ReadyCondition            = "Ready"
	ServicePortNotFoundReason = "ServicePortNotFound"
	ServiceNotFoundReason     = "ServiceNotFound"
	ServiceBackendReadyReason = "ServiceBackendReady"
)

// ConditionalResource is a resource with conditions
type conditionalResource interface {
	GetStatusConditions() *[]metav1.Condition
}

// setResourceCondition sets the given condition with the given status,
// reason and message on a resource.
func setResourceCondition(resource conditionalResource, condition string, status metav1.ConditionStatus, reason, message string) {
	conditions := resource.GetStatusConditions()

	newCondition := metav1.Condition{
		Type:    condition,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	apimeta.SetStatusCondition(conditions, newCondition)
}

// KeycloakRealmNotReady
func KeycloakRealmNotReady(realm KeycloakRealm, reason, message string) KeycloakRealm {
	setResourceCondition(&realm, ReadyCondition, metav1.ConditionFalse, reason, message)
	return realm
}

// KeycloakRealmReady
func KeycloakRealmReady(realm KeycloakRealm, reason, message string) KeycloakRealm {
	setResourceCondition(&realm, ReadyCondition, metav1.ConditionTrue, reason, message)
	return realm
}

// GetStatusConditions returns a pointer to the Status.Conditions slice
func (in *KeycloakRealm) GetStatusConditions() *[]metav1.Condition {
	return &in.Status.Conditions
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=rc
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// KeycloakRealm is the Schema for the KeycloakRealms API
type KeycloakRealm struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakRealmSpec   `json:"spec,omitempty"`
	Status KeycloakRealmStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeycloakRealmList contains a list of KeycloakRealm
type KeycloakRealmList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakRealm `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakRealm{}, &KeycloakRealmList{})
}
