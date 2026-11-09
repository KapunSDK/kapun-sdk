import ch.ubique.uniffi.plugin.dsl.CargoExtension
import ch.ubique.uniffi.plugin.tasks.CargoBuildTask
import org.gradle.api.attributes.Bundling
import org.gradle.api.tasks.Delete
import org.gradle.kotlin.dsl.configure

plugins {
    // Kotlin & KMP plugins
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.parcelize) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kotlin.atomicfu) apply false
    alias(libs.plugins.compose.multiplatform) apply false
    alias(libs.plugins.sqldelight) apply false
    alias(libs.plugins.jetbrains.kotlin.jvm) apply false

    // Android specific plugins
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.ktorfit) apply false

    // iOS specific plugins
    alias(libs.plugins.skie) apply false

    // Rust plugins
    alias(libs.plugins.uniffi.plugin) apply false

    // Library publishing plugins
    alias(libs.plugins.vanniktech.publish) apply false
}

subprojects {
    pluginManager.withPlugin("ch.ubique.uniffi.plugin") {
        extensions.configure<CargoExtension> {
            // Keep Cargo's shared compilation cache in a visible, dedicated directory.
            // It is intentionally outside Gradle's build directories so `clean` does not remove it.
            targetDirectory.set(rootProject.layout.projectDirectory.dir("cargo-target"))
        }

        // gradle.properties defines this as a Gradle project property, but Cargo/clang only read it
        // from the process environment. Forward it so Rust iOS links use the same deployment target
        // as the Kotlin/Native and Xcode parts of the build.
        tasks.withType<CargoBuildTask>().configureEach {
            additionalEnvironment.put(
                "IPHONEOS_DEPLOYMENT_TARGET",
                rootProject.providers.gradleProperty("IPHONEOS_DEPLOYMENT_TARGET"),
            )
        }
    }
}

val ktlintVersion =
    libs.versions.ktlint.engine
        .get()
val ktlintConfiguration = configurations.create("ktlint")
ktlintConfiguration.attributes {
    attribute(
        Bundling.BUNDLING_ATTRIBUTE,
        objects.named(Bundling::class.java, Bundling.SHADOWED),
    )
}
dependencies.add(ktlintConfiguration.name, "com.pinterest.ktlint:ktlint-cli:$ktlintVersion")

val kotlinFiles =
    fileTree(rootDir) {
        include("**/*.kt", "**/*.kts")
        exclude("**/build/**", "**/.gradle/**", "**/uniffi/**")
    }
val ktlintFileArguments =
    kotlinFiles.files
        .map { it.relativeTo(rootDir).invariantSeparatorsPath }
        .sorted()

tasks.register<JavaExec>("ktlintCheck") {
    group = "verification"
    description = "Checks Kotlin source and Gradle scripts with ktlint"
    classpath = ktlintConfiguration
    mainClass.set("com.pinterest.ktlint.Main")
    args("--relative")
    args(ktlintFileArguments)
}

tasks.register<JavaExec>("ktlintFormat") {
    group = "formatting"
    description = "Formats Kotlin source and Gradle scripts with ktlint"
    classpath = ktlintConfiguration
    mainClass.set("com.pinterest.ktlint.Main")
    args("--format")
    args(ktlintFileArguments)
}

// `clean` intentionally preserves the shared Rust cache. Use this task when a completely fresh
// Cargo build is needed or when reclaiming disk space.
tasks.register<Delete>("cleanCargoCache") {
    group = "build"
    description = "Delete the shared Cargo target directory"
    delete(layout.projectDirectory.dir("cargo-target"))
}

allprojects {
    group = "org.kapunsdk"
    version = getProjectVersion()
}

private fun getProjectVersion(): String {
    val versionFromGradleProperties = runCatching { property("ARTIFACT_VERSION").toString() }.getOrNull()
    val versionFromWorkflow = runCatching { property("githubRefName").toString().removePrefix("v") }.getOrNull()
    return versionFromWorkflow ?: versionFromGradleProperties ?: "untagged"
}
