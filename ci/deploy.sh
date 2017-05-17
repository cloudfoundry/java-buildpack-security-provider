#!/usr/bin/env sh

set -e

cd java-buildpack-security-provider
./mvnw -q -Dmaven.test.skip=true deploy
