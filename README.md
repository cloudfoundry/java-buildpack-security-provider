# Java Buildpack Security Provider

[![CI](https://github.com/cloudfoundry/java-buildpack-security-provider/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cloudfoundry/java-buildpack-security-provider/actions/workflows/ci.yml)

The `java-buildpack-security-provider` is a utility that watches for changes to container identity and trust stores and dynamically updates the KeyManager and TrustManager of an application.

The [Java buildpack](https://github.com/cloudfoundry/java-buildpack/blob/main/docs/framework-container_security_provider.md) installs it in every Java application; its documentation covers what it adds and how to disable the KeyManager or TrustManager.

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
