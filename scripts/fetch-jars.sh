#!/bin/bash
set -e
rm -rfv assets
mkdir -p assets
GH_REPO=adorsys/keycloak-config-cli gh release download -p '*.jar' -D assets
