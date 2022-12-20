#!/bin/bash
set -e

GH_REPO=adorsys/keycloak-config-cli gh release list | grep -v "Pre-release" | grep v5 | awk '{ print $2 }' | tac | while read l; do
  echo $l;
  GH_REPO=adorsys/keycloak-config-cli gh release download $l -p '*.jar' -D assets/$l;
  cp -f assets/$l/*.jar assets/
  rm -rf assets/$l
done

ls -l assets
