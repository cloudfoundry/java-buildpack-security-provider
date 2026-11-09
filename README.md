# Java Buildpack Security Provider

[![CI](https://github.com/cloudfoundry/java-buildpack-security-provider/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cloudfoundry/java-buildpack-security-provider/actions/workflows/ci.yml)

The `java-buildpack-security-provider` is a utility that watches for changes to container identity and trust stores and dynamically updates the KeyManager and TrustManager of an application.

The [Java buildpack](https://github.com/cloudfoundry/java-buildpack/blob/main/docs/framework-container_security_provider.md) installs it in every Java application; its documentation covers what it adds and how to disable the KeyManager or TrustManager.

## Certificate rotation
The KeyManager is reloaded when the instance identity certificate (`CF_INSTANCE_CERT`) changes. The Diego executor [writes the new private key (`CF_INSTANCE_KEY`) before the new certificate](https://github.com/cloudfoundry/executor/blob/208a08c51850167d93e1040cfd8538fc1925c882/depot/containerstore/instance_identity_handler.go#L94-L102), so only the certificate file is watched. Since 1.22.0, each load logs the certificate serial, subject and when the certificate chain expires (earliest expiry in the chain, in UTC).

Since 1.22.0, the private key is checked against the certificate on every load. Only RSA keys, the type the Diego executor issues, are checked; other key types are accepted with an informational log message. On a reload with a mismatch or an empty certificate file, the current KeyManager is kept and an error is logged (JUL level `SEVERE`, shown as `ERROR` through SLF4J or Spring Boot):

```
Private key ... does not match certificate ..., keeping current KeyManager (certificate chain expires at 2026-10-15T09:30:00Z). The private key may not have been replaced before the certificate
```

On the first load there is no current KeyManager to keep: a mismatched pair or an empty certificate file is not installed and an error is logged. No client certificate is presented until a certificate change brings a matching pair; other TLS connections keep working.

```
Private key ... does not match certificate ..., no KeyManager installed: no client certificate is presented until a matching pair is loaded
```

A kept KeyManager is not replaced until the next certificate change. With Diego defaults (24 hour validity, rotation 30 minutes before expiry) the kept certificate expires about 30 minutes later, after which TLS handshakes using it fail. A loaded certificate chain that has already expired is installed as before, with an error:

```
Certificate chain ... expired at 2026-10-15T09:30:00Z, TLS handshakes using it will fail
```

Alert on these errors and restart the affected instance to get a new key pair:

```shell
$ cf restart-app-instance APP_NAME INDEX
```

## Logging
The provider logs through `java.util.logging`, with loggers named after its classes in the `org.cloudfoundry.security` package. At the default `INFO` level it logs each certificate load. `FINE` adds details such as the file events seen by the watcher, which show the order in which the certificate and private key files were replaced:

```
FINE org.cloudfoundry.security.FileWatcher: Discarding unimportant file change: instance.key
INFO org.cloudfoundry.security.FileWatchingX509ExtendedKeyManager: Updated KeyManager for ...
```

In a Spring Boot application, set the level like any other logger, e.g. with the environment variable `LOGGING_LEVEL_ORG_CLOUDFOUNDRY_SECURITY=DEBUG`. Otherwise, point `java.util.logging` at a configuration file shipped with the application, e.g. with `JAVA_OPTS: -Djava.util.logging.config.file=<path>`; the file replaces the default configuration, so it needs a handler as well:

```properties
handlers=java.util.logging.ConsoleHandler
java.util.logging.ConsoleHandler.level=FINE
org.cloudfoundry.security.level=FINE
```

## Development
The project depends on Java 8.  To build from source, run the following:

```shell
$ ./mvnw clean package
```

See [docs/RELEASE.md](docs/RELEASE.md) for how to cut a release, how it reaches the Java buildpack, and how dependency updates are handled.

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/java-buildpack-security-provider/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
