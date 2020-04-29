# Java Buildpack Security Provider

| Job | Status
| --- | ------
| `unit-test-8` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/security-provider/jobs/unit-test-8/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/security-provider/jobs/unit-test-8)
| `deploy` | [![deploy-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/security-provider/jobs/deploy/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/security-provider/jobs/deploy)

The `java-buildpack-security-provider` is a utility that watches for changes to container identity and trust stores and dynamically updates the KeyManager and TrustManager of an application.

## Development
The project depends on Java 8.  To build from source, run the following:

```shell
$ ./mvnw clean package
```

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/security-provider/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
