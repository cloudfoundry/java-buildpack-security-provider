# Java Buildpack Security Provider

| Job | Status
| --- | ------
| `unit-test` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/java-buildpack-security-provider/jobs/unit-test-master/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/java-buildpack-security-provider/jobs/unit-test-master)
| `deploy` | [![deploy-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/java-buildpack-security-provider/jobs/deploy-master/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/java-buildpack-security-provider/jobs/deploy-master)

The `java-buildpack-security-provider` is a utility that watches for changes to container identity and trust stores and dynamically updates the KeyManager and TrustManager of an application.

## Development
The project depends on Java 7.  To build from source, run the following:

```shell
$ ./mvnw clean package
```

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/java-buildpack-security-provider/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
