# Java Buildpack Security Provider

| Job | Status
| --- | ------
| `unit-test-8` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/security-provider/jobs/unit-test-8/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/security-provider/jobs/unit-test-8)
| `deploy` | [![deploy-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/security-provider/jobs/deploy/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/security-provider/jobs/deploy)

The `java-buildpack-security-provider` is a utility that watches for changes to container identity and trust stores and dynamically updates the KeyManager and TrustManager of an application.

## Certificate rotation
The KeyManager is reloaded when the instance identity certificate (`CF_INSTANCE_CERT`) changes. The Diego executor writes the new private key (`CF_INSTANCE_KEY`) before the new certificate, so only the certificate file is watched. Each load logs the certificate serial, subject and when the certificate chain expires (earliest expiry in the chain, in UTC).

Before replacing the KeyManager, the private key is checked against the certificate. Only RSA keys, the type the Diego executor issues, are checked; other key types are accepted with an informational log message. On a mismatch or an empty certificate file the current KeyManager is kept and a warning is logged:

```
Private key ... does not match certificate ..., keeping current KeyManager (certificate chain expires at 2026-10-15T09:30:00Z)
```

This is not retried. With Diego defaults (24 hour validity, rotation 30 minutes before expiry) the kept certificate expires about 30 minutes later, after which TLS handshakes using it fail. A loaded certificate chain that has already expired is installed as before, with a warning:

```
Certificate chain ... expired at 2026-10-15T09:30:00Z, TLS handshakes using it will fail
```

Alert on these warnings and restart the affected instance to get a new key pair:

```shell
$ cf restart-app-instance APP_NAME INDEX
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

[e]: https://github.com/cloudfoundry/security-provider/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
