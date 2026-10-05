# Releasing

A release is made from the GitHub UI: publish a release with a new `vX.Y.Z` tag, and the **Release** workflow builds that tag as version `X.Y.Z` and attaches the jars. No version-bump commit or pull request is needed first.

## Versions

The POM uses `${revision}` as its version. The development value lives in one place, the `revision` property in `pom.xml`:

```xml
<revision>1.21.0-SNAPSHOT</revision>
```

Builds override it on the command line: a release with `-Drevision=X.Y.Z` from its tag, the CI snapshot build with `-Drevision=<base>-<short sha>-SNAPSHOT`, e.g. `1.21.0-a1b2c3d-SNAPSHOT`, so every snapshot jar records the commit it was built from.

The `flatten-maven-plugin` writes the resolved version into the installed and deployed POM, so no published POM contains `${revision}`.

The files at a release tag therefore still say `-SNAPSHOT`; the tag name is the record of the version. The `revision` property is the only version to edit by hand.

Earlier releases of this project used a `X.Y.Z.RELEASE`/`X.Y.Z.BUILD-SNAPSHOT` suffix (e.g. `1.20.0.RELEASE`). New releases drop that suffix in favor of plain semantic versions (e.g. `1.21.0`), matching the scheme above.

## Making a release

1. GitHub -> **Releases** -> **Draft a new release**.
2. **Choose a tag**: type a new tag `vX.Y.Z` (e.g. `v1.21.0`) and select **Create new tag on publish**, with target `main`.
3. **Generate release notes**, edit as needed.
4. **Publish release**.

The **Release** workflow then:

1. checks the tag has the form `vX.Y.Z`;
2. checks out the tag and runs `./mvnw -Prelease -Drevision=X.Y.Z verify`, the full test suite included. The `release` profile's `maven-enforcer-plugin` rules fail the build if the project or any dependency is still a `-SNAPSHOT`;
3. attaches `java-buildpack-container-security-provider-X.Y.Z.jar` with its `-sources` and `-javadoc` jars to the release.

### When the workflow fails

Nothing is attached. Fix the cause, then either:

- delete the release **and** its tag (Releases -> the release -> Delete; Tags -> the tag -> Delete) and publish again, or
- if the tag is right and only the build failed for an unrelated reason, re-run it: **Actions -> Release -> Run workflow** with the tag (e.g. `v1.21.0`). This rebuilds the tag and replaces the attached artifacts.

## After a release

Nothing has to be merged: `main` keeps building as `-SNAPSHOT`. When convenient, raise the `revision` property in `pom.xml` to the next development version (e.g. `1.21.1-SNAPSHOT`) in a normal pull request, so snapshot builds no longer look older than the release; releases do not depend on it.

Automating that bump would need the workflow to push to the protected `main`. It needs a repository admin to allow it, either by letting Actions open pull requests (Settings -> Actions -> General -> *Allow GitHub Actions to create and approve pull requests*) or by giving a GitHub App or deploy key a bypass on the branch protection.

## Rebuilding a release locally

The same command the Release workflow runs, with the release checks and tests:

```shell
$ git checkout v1.21.0
$ ./mvnw -Prelease -Drevision=1.21.0 verify
```

## Getting a release into the Java buildpack

The Java buildpack's `manifest.yml` lists this dependency (`container-security-provider`) with a download `uri`, `sha256` and `version`; the `uri` can point at any URL, including a jar attached to a GitHub release.

Updates are picked up automatically: the Cloud Foundry dependency pipeline ([`buildpacks-ci` `dependency-builds`](https://github.com/cloudfoundry/buildpacks-ci/blob/master/pipelines/dependency-builds/config.yml)) watches this repository's GitHub releases directly (`source_type: github_releases`, matching the `java-buildpack-container-security-provider-*.jar` release asset), the same way the sibling `java-buildpack-client-certificate-mapper` dependency is tracked — no Maven Central involved. For a new release it opens a pull request on `cloudfoundry/java-buildpack` that updates the `container-security-provider` entry in `manifest.yml`.

No manual `manifest.yml` pull request is needed for routine releases; only step is publishing the GitHub release as described above.

The rolling **snapshot** release (updated on every push to `main` by the **CI** workflow) is for testing only.
