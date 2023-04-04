#!/usr/bin/env bash

set -euo pipefail

[[ -d $PWD/maven && ! -d $HOME/.m2 ]] && ln -s $PWD/maven $HOME/.m2

REPOSITORY="${PWD}"/repository

cd java-buildpack-security-provider
./mvnw -q -Dmaven.test.skip=true deploy -DcreateChecksum=true -DaltDeploymentRepository="local::default::file://${REPOSITORY}"
