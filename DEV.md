Developer Notes
===============

This document contains notes for developers working on the project.

Coding style
------------

The project uses [editorconfig](https://editorconfig.org/) to enforce a consistent coding style. Please make sure your editor supports it.

Naming conventions
------------------

- No all capital abbreviations in class names. For example, use `Abac` instead of `ABAC`.
- In unit test cases, use the method naming style: ```<MethodUnderTest>_<Condition>_<Scenario>_<ExpectedResult>```. 
  For example, `evaluatePolicy_GivenSingleRequest_WhenPolicyIsTrue_ThenReturnsTrue`.

Release
-------

This project uses Gradle release plugin to manage releases. To release a new version, run the following command:

```bash
./gradlew release
```

If running manually a few questions must be answered:

- The version to be released. Ex: 1.0.0
- The next version to be developed. Ex: 1.0.1-SNAPSHOT

Publish
-------

The project currently publish to local Nexus maven repository.
To publish a new snapshot version, run the following command:

```bash
./gradlew publish
```

To publish a new release version, switch to the release tag first and publish.

```bash
git checkout 1.0.0
./gradlew publish
```
