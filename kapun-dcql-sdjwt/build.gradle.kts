import ch.ubique.uniffi.plugin.extensions.useRustUpLinker

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.skie)
    alias(libs.plugins.vanniktech.publish)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.uniffi.plugin)
}

kotlin {
    compilerOptions { freeCompilerArgs.add("-Xexpect-actual-classes") }
    jvmToolchain(17)
    android {
        namespace = "org.kapunsdk.dcql.sdjwt"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()
        withHostTest {}
        optimization {
            consumerKeepRules.publish = true
            consumerKeepRules.file(rootProject.file("consumer-jna-rules.pro"))
        }
    }
    jvm()
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework { baseName = "kapun-dcql-sdjwt"; isStatic = true }
        target.compilations.configureEach { useRustUpLinker() }
    }
    sourceSets {
        commonMain.dependencies {
            api(project(":kapun-credential-core"))
            api(project(":kapun-dcql"))
            implementation(project(":kapun-util"))
            implementation(project(":kapun-crypto"))
            implementation(libs.kotlin.serialization)
            implementation(libs.ktor.client.cio)
            implementation(libs.ktor.serialization.json)
            implementation(libs.ktor.client.content.negotiation)
        }
        commonTest.dependencies { implementation(libs.kotlin.test) }
        androidMain.dependencies { implementation("net.java.dev.jna:jna:5.18.1@aar") }
    }
}

skie { analytics { enabled = false; disableUpload = true } }
uniffi {
    bindgenFromGitTag("https://github.com/UbiqueInnovation/uniffi-kotlin-multiplatform-bindings.git", libs.versions.uniffi.bindgen.get())
    generateFromLibrary()
}
cargo { packageDirectory = layout.projectDirectory.dir("rust"); ndkVersion = libs.versions.android.ndk.get() }
mavenPublishing {
    coordinates(artifactId = property("ARTIFACT_ID").toString(), version = project.version.toString())
    publishToMavenCentral(true)
}
