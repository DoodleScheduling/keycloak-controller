# k8skeycloak-controller

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/4787/badge)](https://bestpractices.coreinfrastructure.org/projects/4787)
[![e2e](https://github.com/DoodleScheduling/k8skeycloak-controller/workflows/e2e/badge.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/actions)
[![report](https://goreportcard.com/badge/github.com/DoodleScheduling/k8skeycloak-controller)](https://goreportcard.com/report/github.com/DoodleScheduling/k8skeycloak-controller)
[![license](https://img.shields.io/github/license/DoodleScheduling/k8skeycloak-controller.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/blob/main/LICENSE)
[![release](https://img.shields.io/github/release/DoodleScheduling/k8skeycloak-controller/all.svg)](https://github.com/DoodleScheduling/k8skeycloak-controller/releases)

Reconcile a keycloak realm. Under the hood the controller is a wrapper around [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli)
which implements the entire realm update using the Keycloak REST API.

## Example KeycloakRealm

The realm is the entire representation of the realm and is synced accordingly.
It supports secrets substition to inject secrets from kubernetes secrets.
You can use `${secret:secretName:secretField}` anywhere in the realm definition.

```yaml
apiVersion: keycloak.infra.doodle.com/v1beta1
kind: KeycloakRealm
metadata:
  name: doodle
  namespace: default
spec:
  address: http://keycloak-iam-http
  authSecret:
    name: admin-credentials
  interval: 10m
  suspend: false
  realm:
    identityProviders:
    - addReadTokenRoleOnCreate: false
      alias: microsoft
      authenticateByDefault: false
      config:
        clientId: d54681b1-27ae-4246-803c-1d2bf40b636b-test2
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
        clientId: dedeed
        clientSecret: ${secret:github:clientSecret}
        syncMode: IMPORT
        useJwksUrl: "true"
      enabled: true
      firstBrokerLoginFlowAlias: first broker login
      internalId: 58ed4256-74c7-497f-9ac0-86b864d7a7b5
      linkOnly: false
      providerId: github
      storeToken: false
      trustEmail: false
      updateProfileFirstLoginMode: "on"
    internationalizationEnabled: false
    loginTheme: doodle
    loginWithEmailAllowed: true
    maxDeltaTimeSeconds: 43200
    maxFailureWaitSeconds: 900
    minimumQuickLoginWaitSeconds: 60
    notBefore: 0
    keycloakVersion: 15.0.2
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
| `HTTP_ADDR` | The address of the http keycloak. | `:8080` |
| `ENABLE_LEADER_ELECTION` | Enable leader election for controller manager. | `false` |
| `LEADER_ELECTION_NAMESPACE` | Change the leader election namespace. This is by default the same where the controller is deployed. | `` |
| `NAMESPACES` | The controller listens by default for all namespaces. This may be limited to a comma delimted list of dedicated namespaces. | `` |
| `CONCURRENT` | The number of concurrent reconcile workers.  | `4` |
