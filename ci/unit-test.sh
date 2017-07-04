#!/usr/bin/env sh

set -e -u

cd java-buildpack-security-provider
./mvnw -q -Dmaven.repo.local=../m2/repository -Dmaven.user.home=../m2 package
