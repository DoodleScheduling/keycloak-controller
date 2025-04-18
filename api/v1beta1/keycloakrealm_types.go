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
	corev1 "k8s.io/api/core/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
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

// KeycloakRealmSpec defines the desired state of KeycloakRealm
type KeycloakRealmSpec struct {
	// +required
	Address string `json:"address,omitempty"`

	// Contains a credentials set of a user with enough permission to manage keycloak
	AuthSecret SecretReference `json:"authSecret,omitempty"`

	// Interval reconciliation
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`

	// Timeout
	// +optional
	// +deprecated
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Suspend reconciliation
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Reconciler defines the pod spec for the reconciler
	// +optional
	ReconcilerTemplate *ReconcilerTemplate `json:"reconcilerTemplate,omitempty"`

	// Version is the keycloak version
	// +optional
	Version string `json:"version"`

	// Realm is the unstructured keycloak realm representation
	// +optional
	Realm KeycloakAPIRealm `json:"realm"`

	// ResourceSelector defines a selector to select keycloak resources associated with this realm
	ResourceSelector *metav1.LabelSelector `json:"resourceSelector,omitempty"`
}

type ReconcilerTemplate struct {
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	ObjectMetadata `json:"metadata,omitempty"`

	// Specification of the desired behavior of the pod.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	// +optional
	Spec corev1.PodSpec `json:"spec,omitempty"`
}

type ObjectMetadata struct {
	// Map of string keys and values that can be used to organize and categorize
	// (scope and select) objects. May match selectors of replication controllers
	// and services.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations is an unstructured key value map stored with a resource that may be
	// set by external tools to store and retrieve arbitrary metadata. They are not
	// queryable and should be preserved when modifying objects.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
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
	// Conditions holds the conditions for the KeycloakRealm.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last generation reconciled by the controller
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ObservedSHA256 is the last realm checksum reconciled by the controller
	ObservedSHA256 string `json:"observedSHA256,omitempty"`

	// Reconciler is the reconciler pod while a reconciliation is in progress
	Reconciler string `json:"reconciler,omitempty"`

	// LastFailedRequests failed requests
	// +optional
	LastFailedRequests []RequestStatus `json:"lastFailedRequests,omitempty"`

	// SubResourceCatalog holds references to all sub resources including KeycloakClient and KeycloakUser associated with this realm
	SubResourceCatalog []ResourceReference `json:"subResourceCatalog,omitempty"`
}

// ResourceReference metadata to lookup another resource
type ResourceReference struct {
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
}

// RequestStatus knows details about a keycloak API request
type RequestStatus struct {
	URL          string          `json:"url,omitempty"`
	Verb         string          `json:"verb,omitempty"`
	SentAt       metav1.Time     `json:"sentAt,omitempty"`
	Duration     metav1.Duration `json:"duration,omitempty"`
	ResponseCode int             `json:"responseCode,omitempty"`
	ResponseBody string          `json:"responseBody,omitempty"`
	Error        string          `json:"error,omitempty"`
}

func KeycloakRealmReconciling(realm KeycloakRealm, status metav1.ConditionStatus, reason, message string) KeycloakRealm {
	setResourceCondition(&realm, ConditionReconciling, status, reason, message, realm.Generation)
	return realm
}

func KeycloakRealmReady(realm KeycloakRealm, status metav1.ConditionStatus, reason, message string) KeycloakRealm {
	setResourceCondition(&realm, ConditionReady, status, reason, message, realm.Generation)
	return realm
}

// GetStatusConditions returns a pointer to the Status.Conditions slice
func (in *KeycloakRealm) GetStatusConditions() *[]metav1.Condition {
	return &in.Status.Conditions
}

func (in *KeycloakRealm) GetConditions() []metav1.Condition {
	return in.Status.Conditions
}

func (in *KeycloakRealm) SetConditions(conditions []metav1.Condition) {
	in.Status.Conditions = conditions
}

type KeycloakAPIRealm struct {
	// ID is the internal keycloak id
	// +optional
	ID string `json:"id,omitempty"`
	// Realm name. Will fallack to .metadata.name if ommited.
	Realm string `json:"realm,omitempty"`
	// Realm enabled flag.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Realm display name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// Realm HTML display name.
	// +optional
	DisplayNameHTML string `json:"displayNameHtml,omitempty"`
	// Realm Password Policy
	// +optional
	PasswordPolicy string `json:"passwordPolicy,omitempty"`
	// A set of Keycloak Users.
	// +optional
	Users []KeycloakAPIUser `json:"users,omitempty"`
	// A set of Keycloak Clients.
	// +optional
	Clients []KeycloakAPIClient `json:"clients,omitempty"`
	// A set of Identity Providers.
	// +optional
	IdentityProviders []KeycloakIdentityProvider `json:"identityProviders,omitempty"`
	// A set of Identity Provider Mappers.
	// +optional
	IdentityProviderMappers []KeycloakIdentityProviderMapper `json:"identityProviderMappers,omitempty"`
	// A set of Event Listeners.
	// +optional
	EventsListeners []string `json:"eventsListeners,omitempty"`
	// Enable events recording
	// TODO: change to values and use kubebuilder default annotation once supported
	// +optional
	EventsEnabled *bool `json:"eventsEnabled,omitempty"`
	// Enabled event types
	// +optional

	Groups []KeycloakAPIGroup `json:"groups,omitempty"`

	EnabledEventTypes []string `json:"enabledEventTypes,omitempty"`
	// Enable events recording
	// TODO: change to values and use kubebuilder default annotation once supported
	// +optional
	AdminEventsEnabled *bool `json:"adminEventsEnabled,omitempty"`
	// Enable admin events details
	// TODO: change to values and use kubebuilder default annotation once supported
	// +optional
	AdminEventsDetailsEnabled *bool `json:"adminEventsDetailsEnabled,omitempty"`

	// Client scopes
	// +optional
	ClientScopes []KeycloakClientScope `json:"clientScopes,omitempty"`

	// Default client scopes to add to all new clients
	// +optional
	DefaultDefaultClientScopes []string `json:"defaultDefaultClientScopes,omitempty"`

	// Authentication flows
	// +optional
	AuthenticationFlows []KeycloakAPIAuthenticationFlow `json:"authenticationFlows,omitempty"`

	// Authenticator config
	// +optional
	AuthenticatorConfig []KeycloakAPIAuthenticatorConfig `json:"authenticatorConfig,omitempty"`

	// Point keycloak to an external user provider to validate
	// credentials or pull in identity information.
	// +optional
	UserFederationProviders []KeycloakAPIUserFederationProvider `json:"userFederationProviders,omitempty"`

	// User federation mappers are extension points triggered by the
	// user federation at various points.
	// +optional
	UserFederationMappers []KeycloakAPIUserFederationMapper `json:"userFederationMappers,omitempty"`

	// User registration
	// +optional
	RegistrationAllowed *bool `json:"registrationAllowed,omitempty"`
	// Email as username
	// +optional
	RegistrationEmailAsUsername *bool `json:"registrationEmailAsUsername,omitempty"`
	// Edit username
	// +optional
	EditUsernameAllowed *bool `json:"editUsernameAllowed,omitempty"`
	// Forgot password
	// +optional
	ResetPasswordAllowed *bool `json:"resetPasswordAllowed,omitempty"`
	// Remember me
	// +optional
	RememberMe *bool `json:"rememberMe,omitempty"`
	// Verify email
	// +optional
	VerifyEmail *bool `json:"verifyEmail,omitempty"`
	// Login with email
	// +optional
	LoginWithEmailAllowed *bool `json:"loginWithEmailAllowed,omitempty"`
	// Duplicate emails
	// +optional
	DuplicateEmailsAllowed *bool `json:"duplicateEmailsAllowed,omitempty"`
	// Require SSL
	// +optional
	SslRequired string `json:"sslRequired,omitempty"`

	// Brute Force Detection
	// +optional
	BruteForceProtected *bool `json:"bruteForceProtected,omitempty"`
	// Permanent Lockout
	// +optional
	PermanentLockout *bool `json:"permanentLockout,omitempty"`
	// Max Login Failures
	// +optional
	FailureFactor *int32 `json:"failureFactor,omitempty"`
	// Wait Increment
	// +optional
	WaitIncrementSeconds *int32 `json:"waitIncrementSeconds,omitempty"`
	// Quick Login Check Milli Seconds
	// +optional
	QuickLoginCheckMilliSeconds *int64 `json:"quickLoginCheckMilliSeconds,omitempty"`
	// Minimum Quick Login Wait
	// +optional
	MinimumQuickLoginWaitSeconds *int32 `json:"minimumQuickLoginWaitSeconds,omitempty"`
	// Max Wait
	// +optional
	MaxFailureWaitSeconds *int32 `json:"maxFailureWaitSeconds,omitempty"`
	// Failure Reset Time
	// +optional
	MaxDeltaTimeSeconds *int32 `json:"maxDeltaTimeSeconds,omitempty"`

	// Email
	// +optional
	SMTPServer map[string]string `json:"smtpServer,omitempty"`

	// Login Theme
	// +optional
	LoginTheme string `json:"loginTheme,omitempty"`
	// Account Theme
	// +optional
	AccountTheme string `json:"accountTheme,omitempty"`
	// Admin Console Theme
	// +optional
	AdminTheme string `json:"adminTheme,omitempty"`
	// Email Theme
	// +optional
	EmailTheme string `json:"emailTheme,omitempty"`
	// Internationalization Enabled
	// +optional
	InternationalizationEnabled *bool `json:"internationalizationEnabled,omitempty"`
	// Supported Locales
	// +optional
	SupportedLocales []string `json:"supportedLocales,omitempty"`
	// Default Locale
	// +optional
	DefaultLocale string `json:"defaultLocale,omitempty"`

	// Roles
	// +optional
	Roles *RolesRepresentation `json:"roles,omitempty"`

	// Default role
	// +optional
	DefaultRole *RoleRepresentation `json:"defaultRole,omitempty"`

	// Scope Mappings
	// +optional
	ScopeMappings []ScopeMappingRepresentation `json:"scopeMappings,omitempty"`
	// Client Scope Mappings
	// +optional
	ClientScopeMappings map[string]ScopeMappingRepresentationArray `json:"clientScopeMappings,omitempty"`

	// Access Token Lifespan For Implicit Flow
	// +optional
	AccessTokenLifespanForImplicitFlow *int32 `json:"accessTokenLifespanForImplicitFlow,omitempty"`
	// Access Token Lifespan
	// +optional
	AccessTokenLifespan *int32 `json:"accessTokenLifespan,omitempty"`

	// User Managed Access Allowed
	// +optional
	UserManagedAccessAllowed *bool `json:"userManagedAccessAllowed,omitempty"`

	// OTP Policy Algorithm
	// +optional
	OtpPolicyAlgorithm string `json:"otpPolicyAlgorithm,omitempty"`

	// OTP Policy Digits
	// +optional
	OtpPolicyDigits *int32 `json:"otpPolicyDigits,omitempty"`

	// OTP Policy Initial Counter
	// +optional
	OtpPolicyInitialCounter *int32 `json:"otpPolicyInitialCounter,omitempty"`

	// OTP Policy Look Ahead Window
	// +optional
	OtpPolicyLookAheadWindow *int32 `json:"otpPolicyLookAheadWindow,omitempty"`

	// OTP Policy Period
	// +optional
	OtpPolicyPeriod *int32 `json:"otpPolicyPeriod,omitempty"`

	// OTP Policy Type
	// +optional
	OtpPolicyType string `json:"otpPolicyType,omitempty"`

	// OTP Supported Applications
	// +optional
	OtpSupportedApplications []string `json:"otpSupportedApplications,omitempty"`

	// Browser authentication flow
	// +optional
	BrowserFlow string `json:"browserFlow,omitempty"`

	// Direct Grant authentication flow
	// +optional
	DirectGrantFlow string `json:"directGrantFlow,omitempty"`

	// Client authentication flow
	// +optional
	ClientAuthenticationFlow string `json:"clientAuthenticationFlow,omitempty"`

	// Reset Credentials authentication flow
	// +optional
	ResetCredentialsFlow string `json:"resetCredentialsFlow,omitempty"`

	// Registration flow
	// +optional
	RegistrationFlow string `json:"registrationFlow,omitempty"`

	// Docker Authentication flow
	// +optional
	DockerAuthenticationFlow string `json:"dockerAuthenticationFlow,omitempty"`

	AccessCodeLifespan                  int32             `json:"accessCodeLifespan,omitempty"`
	AccessCodeLifespanLogin             int32             `json:"accessCodeLifespanLogin,omitempty"`
	AccessCodeLifespanUserAction        int32             `json:"accessCodeLifespanUserAction,omitempty"`
	ActionTokenGeneratedByAdminLifespan int32             `json:"actionTokenGeneratedByAdminLifespan,omitempty"`
	ActionTokenGeneratedByUserLifespan  int32             `json:"actionTokenGeneratedByUserLifespan,omitempty"`
	Attributes                          map[string]string `json:"attributes,omitempty"`
	BrowserSecurityHeaders              map[string]string `json:"browserSecurityHeaders,omitempty"`
	ClientOfflineSessionIdleTimeout     int32             `json:"clientOfflineSessionIdleTimeout,omitempty"`
	ClientOfflineSessionMaxLifespan     int32             `json:"clientOfflineSessionMaxLifespan,omitempty"`
	ClientSessionIdleTimeout            int32             `json:"clientSessionIdleTimeout,omitempty"`
	ClientSessionMaxLifespan            int32             `json:"clientSessionMaxLifespan,omitempty"`
	Components                          extv1.JSON        `json:"components,omitempty"`
	DefaultOptionalClientScopes         []string          `json:"defaultOptionalClientScopes,omitempty"`
	EventsExpiration                    int64             `json:"eventsExpiration,omitempty"`
	OfflineSessionIdleTimeout           int32             `json:"offlineSessionIdleTimeout,omitempty"`
	OfflineSessionMaxLifespan           int32             `json:"offlineSessionMaxLifespan,omitempty"`
	OfflineSessionMaxLifespanEnabled    *bool             `json:"offlineSessionMaxLifespanEnabled,omitempty"`
	RefreshTokenMaxReuse                int32             `json:"refreshTokenMaxReuse,omitempty"`
	RequiredActions                     extv1.JSON        `json:"requiredActions,omitempty"`
	RevokeRefreshToken                  *bool             `json:"revokeRefreshToken,omitempty"`

	SSOSessionIdleTimeout           int32 `json:"ssoSessionIdleTimeout,omitempty"`
	SSOSessionIdleTimeoutRememberMe int32 `json:"ssoSessionIdleTimeoutRememberMe,omitempty"`
	SSOSessionMaxLifespan           int32 `json:"ssoSessionMaxLifespan,omitempty"`
	SSOSessionMaxLifespanRememberMe int32 `json:"ssoSessionMaxLifespanRememberMe,omitempty"`

	NotBefore int32 `json:"notBefore,omitempty"`

	WebAuthnPolicyAcceptableAaguids                           []string `json:"webAuthnPolicyAcceptableAaguids,omitempty"`
	WebAuthnPolicyAttestationConveyancePreference             string   `json:"webAuthnPolicyAttestationConveyancePreference,omitempty"`
	WebAuthnPolicyAuthenticatorAttachment                     string   `json:"webAuthnPolicyAuthenticatorAttachment,omitempty"`
	WebAuthnPolicyAvoidSameAuthenticatorRegister              *bool    `json:"webAuthnPolicyAvoidSameAuthenticatorRegister,omitempty"`
	WebAuthnPolicyCreateTimeout                               int32    `json:"webAuthnPolicyCreateTimeout,omitempty"`
	WebAuthnPolicyPasswordlessAcceptableAaguids               []string `json:"webAuthnPolicyPasswordlessAcceptableAaguids,omitempty"`
	WebAuthnPolicyPasswordlessAttestationConveyancePreference string   `json:"webAuthnPolicyPasswordlessAttestationConveyancePreference,omitempty"`
	WebAuthnPolicyPasswordlessAuthenticatorAttachment         string   `json:"webAuthnPolicyPasswordlessAuthenticatorAttachment,omitempty"`
	WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister  *bool    `json:"webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister,omitempty"`
	WebAuthnPolicyPasswordlessCreateTimeout                   int32    `json:"webAuthnPolicyPasswordlessCreateTimeout,omitempty"`
	WebAuthnPolicyPasswordlessRequireResidentKey              string   `json:"webAuthnPolicyPasswordlessRequireResidentKey,omitempty"`
	WebAuthnPolicyPasswordlessRpEntityName                    string   `json:"webAuthnPolicyPasswordlessRpEntityName,omitempty"`
	WebAuthnPolicyPasswordlessRpId                            string   `json:"webAuthnPolicyPasswordlessRpId,omitempty"`
	WebAuthnPolicyPasswordlessSignatureAlgorithms             []string `json:"webAuthnPolicyPasswordlessSignatureAlgorithms,omitempty"`
	WebAuthnPolicyPasswordlessUserVerificationRequirement     string   `json:"webAuthnPolicyPasswordlessUserVerificationRequirement,omitempty"`
	WebAuthnPolicyRequireResidentKey                          string   `json:"webAuthnPolicyRequireResidentKey,omitempty"`
	WebAuthnPolicyRpEntityName                                string   `json:"webAuthnPolicyRpEntityName,omitempty"`
	WebAuthnPolicyRpId                                        string   `json:"webAuthnPolicyRpId,omitempty"`
	WebAuthnPolicySignatureAlgorithms                         []string `json:"webAuthnPolicySignatureAlgorithms,omitempty"`
	WebAuthnPolicyUserVerificationRequirement                 string   `json:"webAuthnPolicyUserVerificationRequirement,omitempty"`
}

type RoleRepresentationArray []RoleRepresentation

// https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_rolesrepresentation
type RolesRepresentation struct {
	// Client Roles
	// +optional
	Client map[string]RoleRepresentationArray `json:"client,omitempty"`

	// Realm Roles
	// +optional
	Realm []RoleRepresentation `json:"realm,omitempty"`
}

// https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_rolerepresentation
type RoleRepresentation struct {
	// Role Attributes
	// +optional
	Attributes map[string][]string `json:"attributes,omitempty"`

	// Client Role
	// +optional
	ClientRole *bool `json:"clientRole,omitempty"`

	// Composite
	// +optional
	Composite *bool `json:"composite,omitempty"`

	// Composites
	// +optional
	Composites *RoleRepresentationComposites `json:"composites,omitempty"`

	// Container Id
	// +optional
	ContainerID string `json:"containerId,omitempty"`

	// Description
	// +optional
	Description string `json:"description,omitempty"`

	// Id
	// +optional
	ID string `json:"id,omitempty"`

	// Name
	Name string `json:"name"`
}

type ScopeMappingRepresentationArray []ScopeMappingRepresentation

// https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_scopemappingrepresentation
type ScopeMappingRepresentation struct {
	// Client
	// +optional
	Client string `json:"client,omitempty"`

	// Client Scope
	// +optional
	ClientScope string `json:"clientScope,omitempty"`

	// Roles
	// +optional
	Roles []string `json:"roles,omitempty"`

	// Self
	// +optional
	Self string `json:"self,omitempty"`
}

// https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_rolerepresentation-composites
type RoleRepresentationComposites struct {
	// Map client => []role
	// +optional
	Client map[string][]string `json:"client,omitempty"`

	// Realm roles
	// +optional
	Realm []string `json:"realm,omitempty"`
}

// https://www.keycloak.org/docs-api/10.0/rest-api/index.html#_userfederationproviderrepresentation
type KeycloakAPIUserFederationProvider struct {
	// lastSync int32

	// +optional
	ChangedSyncPeriod *int32 `json:"changedSyncPeriod,omitempty"`

	// User federation provider config.
	// +optional
	Config map[string]string `json:"config,omitempty"`

	// The display name of this provider instance.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// +optional
	FullSyncPeriod *int32 `json:"fullSyncPeriod,omitempty"`

	// The ID of this provider
	// +optional
	ID string `json:"id,omitempty"`

	// The priority of this provider when looking up users or adding a user.
	// +optional
	Priority *int32 `json:"priority,omitempty"`

	// The name of the user provider, such as "ldap", "kerberos" or a custom SPI.
	// +optional
	ProviderName string `json:"providerName,omitempty"`
}

// https://www.keycloak.org/docs/11.0/server_admin/#_ldap_mappers
// https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_userfederationmapperrepresentation
type KeycloakAPIUserFederationMapper struct {
	// User federation mapper config.
	// +optional
	Config map[string]string `json:"config,omitempty"`

	// +optional
	Name string `json:"name,omitempty"`

	// +optional
	ID string `json:"id,omitempty"`

	// +optional
	FederationMapperType string `json:"federationMapperType,omitempty"`

	// The displayName for the user federation provider this mapper applies to.
	FederationProviderDisplayName string `json:"federationProviderDisplayName,omitempty"`
}

type KeycloakAPIAuthenticationFlow struct {
	// Alias
	Alias string `json:"alias"`

	// Authentication executions
	AuthenticationExecutions []KeycloakAPIAuthenticationExecution `json:"authenticationExecutions"`

	// Built in
	// +optional
	BuiltIn *bool `json:"builtIn,omitempty"`

	// Description
	// +optional
	Description string `json:"description,omitempty"`

	// ID
	// +optional
	ID string `json:"id,omitempty"`

	// Provider ID
	// +optional
	ProviderID string `json:"providerId,omitempty"`

	// Top level
	// +optional
	TopLevel *bool `json:"topLevel,omitempty"`
}

type KeycloakAPIAuthenticationExecution struct {
	// Authenticator
	Authenticator string `json:"authenticator,omitempty"`

	// Authenticator Config
	// +optional
	AuthenticatorConfig string `json:"authenticatorConfig,omitempty"`

	// Authenticator flow
	// +optional
	AuthenticatorFlow *bool `json:"authenticatorFlow,omitempty"`

	// Flow Alias
	// +optional
	FlowAlias string `json:"flowAlias,omitempty"`

	// Priority
	// +optional
	Priority int32 `json:"priority,omitempty"`

	// Requirement [REQUIRED, OPTIONAL, ALTERNATIVE, DISABLED]
	Requirement string `json:"requirement,omitempty"`

	// User setup allowed
	// +optional
	UserSetupAllowed *bool `json:"userSetupAllowed,omitempty"`
}

type KeycloakAPIAuthenticatorConfig struct {
	// Alias
	Alias string `json:"alias"`

	// Config
	// +optional
	Config map[string]string `json:"config,omitempty"`

	// ID
	// +optional
	ID string `json:"id,omitempty"`
}

type RedirectorIdentityProviderOverride struct {
	// Identity Provider to be overridden.
	IdentityProvider string `json:"identityProvider"`
	// Flow to be overridden.
	// +optional
	ForFlow string `json:"forFlow,omitempty"`
}

type KeycloakClientScope struct {
	// +optional
	Attributes map[string]string `json:"attributes,omitempty"`
	// +optional
	Description string `json:"description,omitempty"`
	// +optional
	ID string `json:"id,omitempty"`
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	Protocol string `json:"protocol,omitempty"`
	// Protocol Mappers.
	// +optional
	ProtocolMappers []KeycloakProtocolMapper `json:"protocolMappers,omitempty"`
}

type KeycloakIdentityProvider struct {
	// Identity Provider Alias.
	// +optional
	Alias string `json:"alias,omitempty"`
	// Identity Provider Display Name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// Identity Provider Internal ID.
	// +optional
	InternalID string `json:"internalId,omitempty"`
	// Identity Provider ID.
	// +optional
	ProviderID string `json:"providerId,omitempty"`
	// Identity Provider enabled flag.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Identity Provider Trust Email.
	// +optional
	TrustEmail *bool `json:"trustEmail,omitempty"`
	// Identity Provider Store to Token.
	// +optional
	StoreToken *bool `json:"storeToken,omitempty"`
	// Adds Read Token role when creating this Identity Provider.
	// +optional
	AddReadTokenRoleOnCreate *bool `json:"addReadTokenRoleOnCreate,omitempty"`
	// Identity Provider First Broker Login Flow Alias.
	// +optional
	FirstBrokerLoginFlowAlias string `json:"firstBrokerLoginFlowAlias,omitempty"`
	// Identity Provider Post Broker Login Flow Alias.
	// +optional
	PostBrokerLoginFlowAlias string `json:"postBrokerLoginFlowAlias,omitempty"`
	// Identity Provider Link Only setting.
	// +optional
	LinkOnly *bool `json:"linkOnly,omitempty"`
	// Identity Provider config.
	// +optional
	Config map[string]string `json:"config,omitempty"`
}

type KeycloakIdentityProviderMapper struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Identity Provider Alias.
	// +optional
	IdentityProviderAlias string `json:"identityProviderAlias,omitempty"`
	// Identity Provider Mapper.
	// +optional
	IdentityProviderMapper string `json:"identityProviderMapper,omitempty"`
	// Identity Provider Mapper config.
	// +optional
	Config map[string]string `json:"config,omitempty"`
}

type KeycloakUserRole struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Composite   *bool  `json:"composite,omitempty"`
	ClientRole  *bool  `json:"clientRole,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
}

type AuthenticatorConfig struct {
	// Authenticator Config Alias.
	// +optional
	Alias string `json:"alias,omitempty"`
	// Authenticator config.
	// +optional
	Config map[string]string `json:"config,omitempty"`
	// Authenticator ID.
	// +optional
	ID string `json:"id,omitempty"`
}

type KeycloakAPIPasswordReset struct {
	// Password Reset Type.
	// +optional
	Type string `json:"type"`
	// Password Reset Value.
	// +optional
	Value string `json:"value"`
	// True if this Password Reset object is temporary.
	// +optional
	Temporary *bool `json:"temporary"`
}

type AuthenticationExecutionInfo struct {
	// Authentication Execution Info Alias.
	// +optional
	Alias string `json:"alias,omitempty"`
	// Authentication Execution Info Config.
	// +optional
	AuthenticationConfig string `json:"authenticationConfig,omitempty"`
	// True if Authentication Flow is enabled.
	// +optional
	AuthenticationFlow *bool `json:"authenticationFlow,omitempty"`
	// True if Authentication Execution Info is configurable.
	// +optional
	Configurable *bool `json:"configurable,omitempty"`
	// Authentication Execution Info Display Name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// Authentication Execution Info Flow ID.
	// +optional
	FlowID string `json:"flowId,omitempty"`
	// Authentication Execution Info ID.
	// +optional
	ID string `json:"id,omitempty"`
	// Authentication Execution Info Index.
	// +optional
	Index int32 `json:"index,omitempty"`
	// Authentication Execution Info Level.
	// +optional
	Level int32 `json:"level,omitempty"`
	// Authentication Execution Info Provider ID.
	// +optional
	ProviderID string `json:"providerId,omitempty"`
	// Authentication Execution Info Requirement.
	// +optional
	Requirement string `json:"requirement,omitempty"`
	// Authentication Execution Info Requirement Choices.
	// +optional
	RequirementChoices []string `json:"requirementChoices,omitempty"`
}

type TokenResponse struct {
	// Token Response Access Token.
	// +optional
	AccessToken string `json:"access_token"`
	// Token Response Expired In setting.
	// +optional
	ExpiresIn int `json:"expires_in"`
	// Token Response Refresh Expires In setting.
	// +optional
	RefreshExpiresIn int `json:"refresh_expires_in"`
	// Token Response Refresh Token.
	// +optional
	RefreshToken string `json:"refresh_token"`
	// Token Response Token Type.
	// +optional
	TokenType string `json:"token_type"`
	// Token Response Not Before Policy setting.
	// +optional
	NotBeforePolicy int `json:"not-before-policy"`
	// Token Response Session State.
	// +optional
	SessionState string `json:"session_state"`
	// Token Response Error.
	// +optional
	Error string `json:"error"`
	// Token Response Error Description.
	// +optional
	ErrorDescription string `json:"error_description"`
}

type KeycloakAPIGroup struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name,omitempty"`
	Path        string              `json:"path,omitempty"`
	RealmRoles  []string            `json:"realmRoles,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
	ClientRoles map[string][]string `json:"clientRoles,omitempty"`
	SubGroups   []extv1.JSON        `json:"subGroups,omitempty"`
}
