# Contributing

Contributions to the Kapun SDK are welcome. For larger changes, open an issue first so the approach can be discussed.

## Before you open a pull request

- Search existing issues and pull requests.
- Keep the change focused and explain the user-facing impact.
- Add or update tests where practical.
- Do not commit private keys, real personal data, credentials, or internal service URLs. Use synthetic fixtures and local test doubles instead.
- Run `git diff --check` before submitting.

## Building and testing

The project uses Gradle and requires JDK 17 or newer. The repository's CI workflow documents the supported build targets. Common commands are:

```bash
./gradlew build
./gradlew allTests
```

Some platform targets require Android SDK, Xcode, or Rust toolchains. If a platform-specific build is not available in your environment, mention that in the pull request.

## Pull requests

Use the pull request template and describe what was changed, how it was validated, and any known limitations. Please keep generated files and unrelated formatting changes out of the pull request unless they are required.

## Reporting problems

Use the [issue templates](.github/ISSUE_TEMPLATE/) for bugs and feature requests. Do not disclose security vulnerabilities in public issues; follow [SECURITY.md](SECURITY.md) instead.
