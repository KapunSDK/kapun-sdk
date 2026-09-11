# Kapun SDK

The Kapun SDK is a Kotlin Multiplatform toolkit for building digital-identity wallets and verifiers on Android and iOS. It includes credential formats, DCQL, issuance, presentation, wallet, cryptography, trust, proximity, and visualization modules.

The repository also contains sample Android wallet and verifier applications and an iOS sample. The samples are demonstrations and may require application-specific wallet or backend configuration.

## What it covers

- Credential formats: ISO mdoc, SD-JWT VC, W3C Verifiable Credentials, BBS, and Open Badges
- Protocols and queries: OpenID4VCI, OpenID4VP, DCQL, and BLE proximity presentation
- Building blocks for wallets, issuers, verifiers, cryptography, trust, and credential visualization

The implementations follow the relevant [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html), [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/), [DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-la), and [Open Badges](https://www.imsglobal.org/spec/ob/v3p0/) specifications.

## Project status

The project is actively evolving. Check the [releases](https://github.com/KapunSDK/kapun-sdk/releases) for published versions; APIs and implementation details may change between releases.

This project evolved from the former Heidi SDK and is now maintained as the Kapun SDK under the KapunSDK organization. Older documentation and package references may still use the Heidi name.

## Prerequisites

- JDK 17 or newer
- Android Studio for the Android samples
- Xcode 15.4 or newer for the iOS sample

## Build the samples

### Android

```bash
./gradlew :examples:android-wallet:assembleDebug
./gradlew :examples:android-wallet:installDebug

./gradlew :examples:android-verifier:assembleDebug
./gradlew :examples:android-verifier:installDebug
```

For a faster local debug build, compile only the ABI used by the connected device:

    ./gradlew :examples:android-wallet:assembleDebug -PandroidAbis=arm64-v8a

Release builds should omit this option so that all supported Android ABIs are included.
The -PandroidAbis option is provided by the UniFFI plugin v1.2.2-rc1.

Use Android-specific Gradle tasks such as assembleDebug rather than the root build task during
app development. The root build also runs JVM targets; on macOS that includes the macOS Rust
library needed by JVM/JNA binding generation.

Rust outputs are shared between SDK modules automatically in this checkout. The root build configures
all UniFFI modules to use .gradle/cargo-target, which is ignored by Git and survives Gradle clean.
This means developers do not need to set CARGO_TARGET_DIR for normal SDK builds.

When the SDK is included in another KMP project, the included SDK build still uses this same
checkout-local directory. If the consumer is configured as a separate Gradle build that does not
load the SDK root build configuration, set the same absolute path in both builds:

    export CARGO_TARGET_DIR="/absolute/path/to/shared/heidi-cargo-target"
    ./gradlew :app:assembleDebug

### iOS

Open `sample-ios-kapun.xcodeproj` in Xcode, select a simulator or device, and run the `sample-ios-kapun` target. Device builds require your own provisioning profile. The sample requires iOS 16 or newer.

If the build needs Android SDK information, set `ANDROID_HOME` and create a root `local.properties` file containing:

```properties
sdk.dir=/path/to/your/android/sdk
```

The sample sources are available in [`examples/android-wallet`](examples/android-wallet), [`examples/android-verifier`](examples/android-verifier), and [`sample-ios-kapun.xcodeproj`](sample-ios-kapun.xcodeproj).

## Use the published SDK

Released artifacts are available from Maven Central. Add `mavenCentral()` to your repositories and depend on the module you need, for example:

```kotlin
dependencies {
    implementation("org.kapunsdk:kapun-wallet:1.0.0")
}
```

Replace `1.0.0` with the release you want.

## Publish locally

To publish JVM artifacts to your local Maven repository:

```bash
./gradlew publishJvmPublicationToMavenLocal -PARTIFACT_VERSION=1.0.0-LOCAL
```

The resulting JVM coordinates use the `org.kapunsdk` group, for example `org.kapunsdk:kapun-trust-jvm:1.0.0-LOCAL`. Publishing all targets requires the corresponding Rust toolchains. Release signing is disabled by default.

## Get involved

Bug reports and feature requests are welcome in the [issue tracker](https://github.com/KapunSDK/kapun-sdk/issues). See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Pull requests should include tests or a short explanation when tests are not applicable.

Please report security vulnerabilities privately according to the [security policy](SECURITY.md). By participating in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

This project is licensed under the Apache License 2.0. See [LICENSE](./LICENSE).
