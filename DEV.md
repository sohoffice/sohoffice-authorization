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