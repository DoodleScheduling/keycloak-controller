# Keycloak controller for kubernetes

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
It supports secrets substition from kubernetes secrets.
A pattern like `${secret:secretName:secretField}` can be used anywhere in the realm.

This would create a realm called default if it does not exists. If it exists it would try to update it according to the specs.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: default
spec:
  address: http://keycloak-http.keycloak/auth
  authSecret:
    name: keycloak-admin
    passwordField: password
    userField: username
  interval: 10m
  suspend: false
  realm:
    realm: test
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
  version: 18.0.2
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
--otel-endpoint string                      Opentelemetry gRPC endpoint (without protocol)
--otel-insecure                             Opentelemetry gRPC disable tls
--otel-service-name string                  Opentelemetry service name (default "keycloak-controller")
--otel-tls-client-cert-path string          Opentelemetry gRPC mTLS client cert path
--otel-tls-client-key-path string           Opentelemetry gRPC mTLS client key path
--otel-tls-root-ca-path string              Opentelemetry gRPC mTLS root CA path
--watch-all-namespaces                      Watch for resources in all namespaces, if set to false it will only watch the runtime namespace. (default true)
--watch-label-selector string               Watch for resources with matching labels e.g. 'sharding.fluxcd.io/shard=shard1'.
```