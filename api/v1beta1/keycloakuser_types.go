package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type KeycloakUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec KeycloakUserSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// KeycloakUserList contains a list of KeycloakUser
type KeycloakUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakUser `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakUser{}, &KeycloakUserList{})
}

// KeycloakUserSpec defines the desired state of KeycloakUser.
// +k8s:openapi-gen=true
type KeycloakUserSpec struct {
	// Selector for looking up KeycloakUser Custom Resources.
	// +optional
	// This field is deprecated
	RealmSelector *metav1.LabelSelector `json:"realmSelector,omitempty"`
	// Keycloak User REST object.
	// +kubebuilder:validation:Required
	User KeycloakAPIUser `json:"user"`
}

type KeycloakAPIUser struct {
	// ID is the internal keycloak id
	// +optional
	ID string `json:"id,omitempty"`
	// Defaults to .metadata.name
	// +optional
	UserName string `json:"username,omitempty"`
	// First Name.
	// +optional
	FirstName string `json:"firstName,omitempty"`
	// Last Name.
	// +optional
	LastName string `json:"lastName,omitempty"`
	// Email.
	// +optional
	Email string `json:"email,omitempty"`
	// True if email has already been verified.
	// +optional
	EmailVerified *bool `json:"emailVerified,omitempty"`
	// User enabled flag.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// A set of Realm Roles.
	// +optional
	RealmRoles []string `json:"realmRoles,omitempty"`
	// A set of Client Roles.
	// +optional
	ClientRoles map[string][]string `json:"clientRoles,omitempty"`
	// A set of Required Actions.
	// +optional
	RequiredActions []string `json:"requiredActions,omitempty"`
	// A set of Groups.
	// +optional
	Groups []string `json:"groups,omitempty"`
	// A set of Federated Identities.
	// +optional
	FederatedIdentities []FederatedIdentity `json:"federatedIdentities,omitempty"`
	// A set of Credentials.
	// +optional
	Credentials []KeycloakCredential `json:"credentials,omitempty"`
	// A set of Attributes.
	// +optional
	Attributes map[string][]string `json:"attributes,omitempty"`
	NotBefore  int32               `json:"notBefore,omitempty"`

	DisableableCredentialTypes []string `json:"disableableCredentialTypes,omitempty"`
	ServiceAccountClientId     string   `json:"serviceAccountClientId,omitempty"`
	TOTP                       *bool    `json:"totp,omitempty"`
}

type KeycloakCredential struct {
	// Credential Type.
	// +optional
	Type string `json:"type,omitempty"`
	// Credential Value.
	// +optional
	Value string `json:"value,omitempty"`
	// True if this credential object is temporary.
	// +optional
	Temporary *bool `json:"temporary,omitempty"`
}

type FederatedIdentity struct {
	// Federated Identity Provider.
	// +optional
	IdentityProvider string `json:"identityProvider,omitempty"`
	// Federated Identity User ID.
	// +optional
	UserID string `json:"userId,omitempty"`
	// Federated Identity User Name.
	// +optional
	UserName string `json:"userName,omitempty"`
}
