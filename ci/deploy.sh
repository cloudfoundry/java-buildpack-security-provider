#!/usr/bin/env sh

set -e -u

ln -fs $PWD/maven $HOME/.m2

cd java-buildpack-security-provider
./mvnw -q -Dmaven.test.skip=true deploy
