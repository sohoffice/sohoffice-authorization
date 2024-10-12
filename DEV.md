Developer Notes
===============

This document contains notes for developers working on the project.

Coding style
------------

The project uses [editorconfig](https://editorconfig.org/) to enforce a consistent coding style. Please make sure your
editor supports it.

Naming conventions
------------------

- No all capital abbreviations in class names. For example, use `Abac` instead of `ABAC`.
- In unit test cases, use the method naming style: ```<MethodUnderTest>_<Condition>_<Scenario>_<ExpectedResult>```.
  For example, `evaluatePolicy_GivenSingleRequest_WhenPolicyIsTrue_ThenReturnsTrue`.

Release
-------

This project uses Gradle release plugin to manage releases.

The root project is only a blanket, and only the sub projects can be released.
For example, to release a new version on "core", run the following command:

```bash
./gradlew :core:release
```

If running manually a few questions must be answered:

- The version to be released. Ex: `1.0.0`

  The value will be automatically determined through version value in current version.properties file.
  In the simplest form, `-SNAPSHOT` is removed from the version.
- The next version to be developed. Ex: 1.0.1-SNAPSHOT

  This is also calculated fro the version value in the version.properties file.
  The number is increased at the patch level.

Release tag will be named in the format `<name>-v<version>`. For example, `core-v1.0.0`.
It will be automatically created by the release plugin.

### Increase major or minor version

To increase major or minor version, do it manually via version.properties file before running the release command.

Publish
-------

The project currently publish to local Nexus maven repository.
To publish a new snapshot version, run the following command:

```bash
./gradlew publish
```

Release version will be published by the release process. No extra steps are needed to publish.
