## Release process

### Controller release
1. Merge all pr's to master which need to be part of the new release
2. Create pr to master and bump the kustomization base
3. Push a tag following semantic versioning prefixed by 'v'. Do not create a github release, this is done automatically.
4. Create a new pr and add the following changes:
  1. Bump chart version
  2. Bump charts app version

### Helm chart change only
1. Bump the helm chart version in the pr