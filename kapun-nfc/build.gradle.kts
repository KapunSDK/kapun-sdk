plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.android.kotlin.multiplatform.library)
	alias(libs.plugins.vanniktech.publish)
}

kotlin {
	jvmToolchain(17)

	android {
		namespace = "org.kapunsdk.nfc"
		compileSdk = libs.versions.android.compileSdk.get().toInt()
		minSdk = libs.versions.android.minSdk.get().toInt()
	}
	jvm()

	sourceSets {
		commonTest.dependencies {
			implementation(libs.kotlin.test)
		}
	}
}

mavenPublishing {
	coordinates(artifactId= property("ARTIFACT_ID").toString(), version= project.version.toString())
	publishToMavenCentral(true)
}
