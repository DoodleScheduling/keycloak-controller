# Keycloak realm controller for kubernetes

[![release](https://img.shields.io/github/release/DoodleScheduling/keycloak-controller/all.svg)](https://github.com/DoodleScheduling/keycloak-controller/releases)
[![release](https://github.com/doodlescheduling/keycloak-controller/actions/workflows/release.yaml/badge.svg)](https://github.com/doodlescheduling/keycloak-controller/actions/workflows/release.yaml)
[![report](https://goreportcard.com/badge/github.com/DoodleScheduling/keycloak-controller)](https://goreportcard.com/report/github.com/DoodleScheduling/keycloak-controller)
[![Coverage Status](https://coveralls.io/repos/github/DoodleScheduling/keycloak-controller/badge.svg?branch=master)](https://coveralls.io/github/DoodleScheduling/keycloak-controller?branch=master)
[![license](https://img.shields.io/github/license/DoodleScheduling/keycloak-controller.svg)](https://github.com/DoodleScheduling/keycloak-controller/blob/master/LICENSE)

Keycloak realm management for kubernetes. Compared to the [keycloak-operator](https://github.com/keycloak/keycloak-operator) this controller actually reconciles the entire realm. The keycloak-operator basically only creates the realm and syncs top level changes only.

This controller supports KeycloakRealm, KeycloakClient and KeycloakUser.
The controller does **not** deploy keycloak, its responsibility is to manage realms for extsing keycloak deployments.
This controller runs great in combination with the official keycloak operator which deploys keycloak while this controller can manage the realm.

Under the hood the controller is a wrapper around the awesome [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli)
which implements the entire realm update using the Keycloak REST API.

## Requirements

A running keycloak is a requirement. This controllers does not manage or deploy keycloak itself.
Also it is required to create a secret which contains the credentials for a user with enough permissions to create/manage realms.

Example:
```yaml
apiVersion: v1
data:
  password: YWRtaW4=
  username: YWRtaW4=
kind: Secret
metadata:
  name: keycloak-admin
```

## Example KeycloakRealm

The realm is the entire representation of the realm and is reconciled accordingly.
This would create a realm called default if it does not exists. If it exists it would try to update it according to these specs.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: default
spec:
  address: http://keycloak-http.keycloak/auth
  authSecret:
    name: keycloak-admin
  interval: 10m
  realm:
    accessCodeLifespan: 60
    accessCodeLifespanLogin: 1800
    accessCodeLifespanUserAction: 300
    accessTokenLifespan: 300
    accessTokenLifespanForImplicitFlow: 900
    accountTheme: test
    actionTokenGeneratedByAdminLifespan: 43200
    actionTokenGeneratedByUserLifespan: 300
    adminEventsDetailsEnabled: true
    adminEventsEnabled: true
    directGrantFlow: direct grant
    displayName: Test
    dockerAuthenticationFlow: docker auth
    duplicateEmailsAllowed: false
    editUsernameAllowed: false
    enabled: true
    eventsEnabled: true
    eventsExpiration: 1209600
    loginTheme: foo
    verifyEmail: true
    waitIncrementSeconds: 60
    webAuthnPolicyAcceptableAaguids: []
    webAuthnPolicyAttestationConveyancePreference: not specified
    webAuthnPolicyAuthenticatorAttachment: not specified
    webAuthnPolicyAvoidSameAuthenticatorRegister: false
    webAuthnPolicyCreateTimeout: 0
    webAuthnPolicyPasswordlessAcceptableAaguids: []
    webAuthnPolicyPasswordlessAttestationConveyancePreference: not specified
    webAuthnPolicyPasswordlessAuthenticatorAttachment: not specified
    webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: false
    webAuthnPolicyPasswordlessCreateTimeout: 0
    webAuthnPolicyPasswordlessRequireResidentKey: not specified
    webAuthnPolicyPasswordlessRpId: ""
    webAuthnPolicyPasswordlessSignatureAlgorithms:
    - ES256
    webAuthnPolicyPasswordlessUserVerificationRequirement: not specified
    webAuthnPolicyRequireResidentKey: not specified
    webAuthnPolicyRpId: ""
    webAuthnPolicySignatureAlgorithms:
    - ES256
    webAuthnPolicyUserVerificationRequirement: not specified
```

### Other resources

The controller supports client and user management as separate resources:

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakClient
metadata:
  name: kc-client-example
spec:
  client:
    access:
      configure: true
      manage: true
      view: true
    attributes:
      backchannel.logout.session.required: "false"
      exclude.session.state.from.auth.response: "true"
    bearerOnly: false
    clientAuthenticatorType: client-secret
    clientId: shortcut
    consentRequired: false
    defaultClientScopes: []
    directAccessGrantsEnabled: false
    enabled: true
    frontchannelLogout: false
    fullScopeAllowed: false
    implicitFlowEnabled: false
    nodeReRegistrationTimeout: -1
    notBefore: 0
    optionalClientScopes: []
    protocol: openid-connect
    protocolMappers: []
    publicClient: true
    redirectUris:
    - https://frontend/
    serviceAccountsEnabled: false
    standardFlowEnabled: true
    webOrigins:
    - +
```

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakUser
metadata:
  name: service-account-kc-client-example
spec:
  user:
    disableableCredentialTypes: []
    emailVerified: false
    enabled: true
    groups: []
    notBefore: 0
    realmRoles:
    - service
    - uma_authorization
    requiredActions: []
    serviceAccountClientId: service-account-kc-client-example
```

If no resource selector on the realm is configured no users nor clients will be included.
`matchLabels: {}` will include all of them in the same namespace as the realm.
By using match lables or expressions it can be configured what resources should be included in the realm.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: default
spec:
  address: http://keycloak-http.keycloak/auth
  resourceSelector:
    matchLabels: {}
  authSecret:
    name: keycloak-admin
    passwordField: password
    userField: username
  interval: 10m
  suspend: false
  realm:
    accessCodeLifespan: 60
    accessCodeLifespanLogin: 1800
    accessCodeLifespanUserAction: 300
    accessTokenLifespan: 300
```

### Secret substitution

All fields support secret subsitution from kubernetes secrets.
A pattern like `${secret:secretName:secretField}` can be used anywhere in the `KeycloakRealm`` `.spec.realm` as
well as in `KeycloakUser` and `KeycloakClient` resources.

**Note**: The secret must be in the same namespace as the KeycloakRealm.

## How does this work?
For each `KeycloakRealm` the controller attempts to create reconciler pod which invokes upstream images from [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli). For each realm beeing reconciled a pod is spinned up in the same namespace the realm lives. If a current reconciliation is in progress one can get the reconciler pod from `.status.reconciler`.
The controller tries to automatically elect the keycloak version however it is possible to overrule this by defining the keycloak version manually on the `KeycloakRealm`` in `.spec.version`.

Previous versions of this controller bundled [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli) artifacts in the controller itself. However this introduced various implications. For instances it was not possible to tweak arguments for [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli) itself by realm. Also shelling out to `java` was a bit of a security concern since the controller image itself also needs to bundle an OpenJDK runtime. 
From version 2.x the controller is refactored into a cloud native approach as described above.

## Reconciler template
It is possible to declare reconciler template which the controller will use to spin up reconciler pods.
In the following example the reconciler receives an additional container called mysidecar. Also resources
are declared on the `keycloak-config-cli` container as well as it will run in debug mode.

**Note**: The keycloak-config-cli container is always called keycloak-config-cli. It is possible to patch that container by using said name as in the example bellow.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: default
spec:
  address: http://keycloak-http.keycloak/auth
  authSecret:
    name: keycloak-admin
  interval: 10m
  realm:
    accessCodeLifespan: 60
    accessCodeLifespanLogin: 1800
    accessCodeLifespanUserAction: 300
    accessTokenLifespan: 300
    accessTokenLifespanForImplicitFlow: 900
    accountTheme: test
  reconcilerTemplate:
    spec:
      containers:
      - name: keycloak-config-cli
        resources:
          request:
            memory: 256Mi
            cpu: 50m
          limit:
            memory: 512Mi
        env:
        - name: LOGGING_LEVEL_ROOT
          value: debug
      - name: random-sidecar
        image: mysidecar
```

## Observe KeycloakRealm reconciliation

A `KeycloakRealm` will have all discovered resources populated in `.status.subResourceCatalog`.
Also there are two conditions which are useful for observing `Ready` and a temporary one named `Reconciling`
as long as a reconciliation is in progress.

`.status.reconciler` references the reconciler pod while a realm has a `Reconciling` condition
and `.status.lastFailedRequests` includes all failed requests from the current reconciliation. 
**Note**: `.status.lastFailedRequests` will only be included if the sidecar proxy is deployed. See the following chapter.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: default
spec:
  address: http://keycloak-http.keycloak/auth
  authSecret:
    name: keycloak-admin
  interval: 10m
  realm:
    accessCodeLifespan: 60
    accessCodeLifespanLogin: 1800
    accessCodeLifespanUserAction: 300
  status:
    conditions:
    - lastTransitionTime: "2023-11-30T12:01:52Z"
      message: back-off 5m0s restarting failed container=keycloak-config-cli pod=keycloakrealm-default-bstr2_examplens(6084edbc-1dac-48de-925f-031df6704a14)
      observedGeneration: 32
      reason: ReconciliationFailed
      status: "False"
      type: Ready
    - lastTransitionTime: "2023-11-24T09:46:42Z"
      message: ""
      observedGeneration: 32
      reason: Progressing
      status: "True"
      type: Reconciling
    lastFailedRequests:
    - duration: 13.584744ms
      responseBody: '{"error":"unknown_error"}'
      responseCode: 500
      sentAt: "2023-11-30T14:17:49Z"
      url: http://keycloak-http.keycloak/auth/admin/realms/default/authentication/flows/362fb405-36ff-4c96-9ec9-625bf8b53d61
      verb: DELETE
    - duration: 24.813138ms
      responseBody: '{"error":"unknown_error"}'
      responseCode: 500
      sentAt: "2023-11-30T14:18:00Z"
      url: http://keycloak-http.keycloak/auth/admin/realms/default/authentication/flows/362fb405-36ff-4c96-9ec9-625bf8b53d61
      verb: DELETE
    lastReconcileDuration: 55.906534ms
    observedGeneration: 32
    reconciler: keycloakrealm-default-bstr2
    subResourceCatalog:
    - apiVersion: keycloak.infra.doodle.com/v1beta1
      kind: KeycloakClient
      name: web-client-1
    - apiVersion: keycloak.infra.doodle.com/v1beta1
      kind: KeycloakClient
      name: web-client-2
    - apiVersion: keycloak.infra.doodle.com/v1beta1
      kind: KeycloakUser
      name: user-example
```

## Use a proxy for advanced request details
The keycloak-controller ships a small proxy for `keycloak-client-config` which can send opentelemtry data as well as 
enhance the KeycloakRealm status with failed requests from `keycloak-client-config`. 
It is recommended to configure all realms to run with the proxy. 

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloakrealm-proxy
rules:
- apiGroups: ["keycloak.infra.doodle.com"]
  resources:
  - keycloakrealms
  verbs: ["get"]
- apiGroups: ["keycloak.infra.doodle.com"]
  resources:
  - keycloakrealms/status
  verbs: ["get", "update", "patch"]
--- 
apiVersion: v1
kind: ServiceAccount
metadata:
  name: keycloakrealm-default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: keycloakrealm-default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: keycloakrealm-default
subjects:
- kind: ServiceAccount
  name: keycloakrealm-default
---
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: default
spec:
  address: http://keycloak-http.keycloak/auth
  authSecret:
    name: keycloak-admin
  interval: 10m
  realm:
    accessCodeLifespan: 60
    accessCodeLifespanLogin: 1800
    accessCodeLifespanUserAction: 300
    accessTokenLifespan: 300
    accessTokenLifespanForImplicitFlow: 900
    accountTheme: test
  reconcilerTemplate:
    spec:
      containers:
      - env:
        - name: KEYCLOAK_HTTPPROXY
          value: http://127.0.0.1:8080
        name: keycloak-config-cli
      - args:
        - --otel-endpoint=opentelemetry-collector.tracing:4317
        - --otel-insecure=true
        env:
        - name: REALM_NAME
          value: default
        - name: REALM_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: PROXY_ADDRESS
          value: 127.0.0.1:8080
        image: ghcr.io/doodlescheduling/keycloak-controller/proxy:v2.0.0
        name: proxy
      serviceAccount: keycloakrealm-default
```

## Installation

### Helm

Please see [chart/keycloak-controller](https://github.com/DoodleScheduling/keycloak-controller/tree/master/chart/keycloak-controller) for the helm chart docs.

### Manifests/kustomize

Alternatively you may get the bundled manifests in each release to deploy it using kustomize or use them directly.

## Dealing with managed realms

The controller tries to reconcile the realm in the specified interval (if specified) or if there is any spec change.
The reconciliation can be paused by setting `spec.suspend` to `true`:

```
kubectl patch keycloakrealms.keycloak.infra.doodle.com myrealm -p '{"spec":{"suspend": true}}' --type=merge
```

This can be very useful if one wants to change and test some settings using the keycloak web ui where the controller should not interfere.

## Configuration
The controller can be configured using cmd args:
```
--concurrent int                            The number of concurrent KeycloakRealm reconciles. (default 4)
--enable-leader-election                    Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.
--graceful-shutdown-timeout duration        The duration given to the reconciler to finish before forcibly stopping. (default 10m0s)
--health-addr string                        The address the health endpoint binds to. (default ":9557")
--insecure-kubeconfig-exec                  Allow use of the user.exec section in kubeconfigs provided for remote apply.
--insecure-kubeconfig-tls                   Allow that kubeconfigs provided for remote apply can disable TLS verification.
--kube-api-burst int                        The maximum burst queries-per-second of requests sent to the Kubernetes API. (default 300)
--kube-api-qps float32                      The maximum queries-per-second of requests sent to the Kubernetes API. (default 50)
--leader-election-lease-duration duration   Interval at which non-leader candidates will wait to force acquire leadership (duration string). (default 35s)
--leader-election-release-on-cancel         Defines if the leader should step down voluntarily on controller manager shutdown. (default true)
--leader-election-renew-deadline duration   Duration that the leading controller manager will retry refreshing leadership before giving up (duration string). (default 30s)
--leader-election-retry-period duration     Duration the LeaderElector clients should wait between tries of actions (duration string). (default 5s)
--log-encoding string                       Log encoding format. Can be 'json' or 'console'. (default "json")
--log-level string                          Log verbosity level. Can be one of 'trace', 'debug', 'info', 'error'. (default "info")
--max-retry-delay duration                  The maximum amount of time for which an object being reconciled will have to wait before a retry. (default 15m0s)
--metrics-addr string                       The address the metric endpoint binds to. (default ":9556")
--min-retry-delay duration                  The minimum amount of time for which an object being reconciled will have to wait before a retry. (default 750ms)
--watch-all-namespaces                      Watch for resources in all namespaces, if set to false it will only watch the runtime namespace. (default true)
--watch-label-selector string               Watch for resources with matching labels e.g. 'sharding.fluxcd.io/shard=shard1'.
```