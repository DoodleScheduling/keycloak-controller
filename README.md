# k8skeycloak-controller

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/4787/badge)](https://bestpractices.coreinfrastructure.org/projects/4787)
[![e2e](https://github.com/DoodleScheduling/k8skeycloak-controller/workflows/e2e/badge.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/actions)
[![report](https://goreportcard.com/badge/github.com/DoodleScheduling/k8skeycloak-controller)](https://goreportcard.com/report/github.com/DoodleScheduling/k8skeycloak-controller)
[![license](https://img.shields.io/github/license/DoodleScheduling/k8skeycloak-controller.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/blob/main/LICENSE)
[![release](https://img.shields.io/github/release/DoodleScheduling/k8skeycloak-controller/all.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/releases)

Keycloak realm declaration for kubernetes. [Compared to the keycloak-operator](https://github.com/keycloak/keycloak-operator) this controller actually reconciles the entire realm throughout all depths. The keycloak-operator basically only creates the realm and syncs top level changes only.
Under the hood the controller is a wrapper around the awesome [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli)
which implements the entire realm update using the Keycloak REST API.

## Example KeycloakRealm

The realm is the entire representation of the realm and is synced accordingly.
It supports secrets substition to inject secrets from kubernetes secrets.
You can use `${secret:secretName:secretField}` anywhere in the realm definition.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: myrealm
  namespace: default
spec:
  address: http://keycloak-iam-http
  authSecret:
    name: admin-credentials
  interval: 10m
  suspend: false
  version: 15.0.2
  realm:
    identityProviders:
    - addReadTokenRoleOnCreate: false
      alias: microsoft
      authenticateByDefault: false
      config:
        clientId: 1b75ccdc-ad62-4fba-b0f0-079720295066
        clientSecret: ${secret:microsoft:clientSecret}
        defaultScope: User.Read
        guiOrder: "10"
        useJwksUrl: "true"
      enabled: true
      firstBrokerLoginFlowAlias: first broker login
      internalId: microsoft
      linkOnly: false
      providerId: microsoft
      storeToken: false
      trustEmail: true
      updateProfileFirstLoginMode: "on"
    - addReadTokenRoleOnCreate: false
      alias: github
      authenticateByDefault: false
      config:
        clientId:  c9b76245-e2b6-496f-827f-eccd3b283496 
        clientSecret: ${secret:github:clientSecret}
        syncMode: IMPORT
        useJwksUrl: "true"
      enabled: true
      firstBrokerLoginFlowAlias: first broker login
      linkOnly: false
      providerId: github
      storeToken: false
      trustEmail: false
      updateProfileFirstLoginMode: "on"
    internationalizationEnabled: false
    loginTheme: default
    loginWithEmailAllowed: true
    maxDeltaTimeSeconds: 43200
    maxFailureWaitSeconds: 900
    minimumQuickLoginWaitSeconds: 60
    notBefore: 0
```

## Helm chart

Please see [chart/k8skeycloak-controller](https://github.com/DoodleScheduling/k8skeycloak-controller) for the helm chart docs.

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
