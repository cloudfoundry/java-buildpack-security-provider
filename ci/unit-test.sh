#!/usr/bin/env sh

set -e

cd java-buildpack-security-provider
./mvnw -q package
