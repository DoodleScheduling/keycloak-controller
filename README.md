# k8skeycloak-controller

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5641/badge)](https://bestpractices.coreinfrastructure.org/projects/5641)
[![e2e](https://github.com/DoodleScheduling/k8skeycloak-controller/workflows/e2e/badge.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/actions)
[![report](https://goreportcard.com/badge/github.com/DoodleScheduling/k8skeycloak-controller)](https://goreportcard.com/report/github.com/DoodleScheduling/k8skeycloak-controller)
[![license](https://img.shields.io/github/license/DoodleScheduling/k8skeycloak-controller.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/blob/master/LICENSE)
[![release](https://img.shields.io/github/release/DoodleScheduling/k8skeycloak-controller/all.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/releases)

Keycloak realm declaration for kubernetes. Compared to the [keycloak-operator](https://github.com/keycloak/keycloak-operator) this controller actually reconciles the entire realm throughout all depths. The keycloak-operator basically only creates the realm and syncs top level changes only.
Under the hood the controller is a wrapper around the awesome [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli)
which implements the entire realm update using the Keycloak REST API.

## Requirements

You need a running keycloak server. This controllers does not manage or deploy keycloak itself but rather manages realms.
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

The realm is the entire representation of the realm and is synced accordingly.
It supports secrets substition to inject secrets from kubernetes secrets.
You can use `${secret:secretName:secretField}` anywhere in the realm definition.

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
  version: 15.0.2
```

## Installation

### Helm

Please see [chart/k8skeycloak-controller](https://github.com/DoodleScheduling/k8skeycloak-controller/tree/master/chart/k8skeycloak-controller) for the helm chart docs.

### Manifests/kustomize

Alternatively you may get the bundled manifests in each release to deploy it using kustomize or use them directly.

## Configure the controller

You may change base settings for the controller using env variables (or alternatively command line arguments).
Available env variables:

| Name  | Description | Default |
|-------|-------------| --------|
| `METRICS_ADDR` | The address of the metric endpoint binds to. | `:9556` |
| `PROBE_ADDR` | The address of the probe endpoints binds to. | `:9557` |
| `ENABLE_LEADER_ELECTION` | Enable leader election for controller manager. | `false` |
| `LEADER_ELECTION_NAMESPACE` | Change the leader election namespace. This is by default the same where the controller is deployed. | `` |
| `NAMESPACES` | The controller listens by default for all namespaces. This may be limited to a comma delimted list of dedicated namespaces. | `` |
| `CONCURRENT` | The number of concurrent reconcile workers.  | `4` |
| `ASSETS_PATH` | The directory where to look for keycloak-config-cli | `/assets` |

## Dealing with managed realms

The controller tries to reconcile the realm in the specified interval (if specified) or if there is any spec change.
The reconciliation can be paused by setting `spec.suspend` to `true`:

```
kubectl patch keycloakrealms.keycloak.infra.doodle.com myrealm -p '{"spec":{"suspend": true}}' --type=merge
```

This can be very useful if one wants to change and test some settings using the keycloak web ui where the controller should not interfere.


## Using alongside keycloak-operator

This controllers also works great in combination with the keycloak-operator.
You may use (KeycloakRealm) keycloakrealms.keycloak.infra.doodle.com to manage the entire realm while for example using the keycloak-operator to manage KeycloakClients only.
