plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.skie)
    alias(libs.plugins.vanniktech.publish)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        freeCompilerArgs.add("-Xwhen-guards")
    }
    jvmToolchain(17)
    android {
        namespace = "org.kapunsdk.credentials.umbrella"
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
        target.binaries.framework {
            baseName = "kapun-credentials"
            isStatic = true
        }
    }
    sourceSets {
        commonMain.dependencies {
            api(project(":kapun-credential-core"))
            api(project(":kapun-dcql"))
            api(project(":kapun-dcql-bbs"))
            api(project(":kapun-dcql-mdoc"))
            api(project(":kapun-dcql-sdjwt"))
            api(project(":kapun-dcql-w3c"))
            api(project(":kapun-dcql-openbadges"))
            implementation(project(":kapun-util"))
            implementation(project(":kapun-crypto"))
            implementation(libs.kotlin.coroutines)
            implementation(libs.kotlin.serialization)
        }
        commonTest.dependencies { implementation(libs.kotlin.test) }
    }
}

skie { analytics { enabled = false; disableUpload = true } }
mavenPublishing {
    coordinates(artifactId = property("ARTIFACT_ID").toString(), version = project.version.toString())
    publishToMavenCentral(true)
}
