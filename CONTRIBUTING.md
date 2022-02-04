## Release process

1. Merge all pr's to master which need to be part of the new release
2. Create pr to master with these changes:
  1. Bump chart version
  2. Bump charts app version
  3. Bump kustomization
  4. Create CHANGELOG.md entry with release and date
3. Merge pr
4. Push a tag following semantic versioning prefixed by 'v'.
Do not create a github release, this is done automatically.
