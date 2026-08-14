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

allprojects {
	group = "org.kapunsdk"
	version = getProjectVersion()

	tasks.matching { it.name.startsWith("sign") && it.name.endsWith("Publication") }.configureEach {
		onlyIf {
			!isMavenLocalPublicationRequested()
		}
	}
}

val localMavenPublicationModules = listOf(
	"kapun-util",
	"kapun-crypto",
	"kapun-proximity",
	"kapun-credentials",
	"kapun-dcql",
	"kapun-presentation",
	"kapun-wallet",
	"kapun-issuance",
	"kapun-trust",
	"kapun-visualization",
)

tasks.register("publishJvmToMavenLocal") {
	group = "publishing"
	description = "Publishes Kapun SDK JVM artifacts to Maven Local. Override the version with -PARTIFACT_VERSION=1.0.0-LOCAL."

	dependsOn(
		localMavenPublicationModules.map { module ->
			project(":$module").tasks.named("publishJvmPublicationToMavenLocal")
		}
	)
}

private fun getProjectVersion(): String {
	val versionFromGradleProperties = runCatching { property("ARTIFACT_VERSION").toString() }.getOrNull()
	val versionFromWorkflow = runCatching { property("githubRefName").toString().removePrefix("v") }.getOrNull()
	return versionFromWorkflow ?: versionFromGradleProperties ?: "untagged"
}

private fun isMavenLocalPublicationRequested(): Boolean =
	gradle.startParameter.taskNames.any { taskName ->
		taskName == "publishJvmToMavenLocal" ||
			taskName == "publishToMavenLocal" ||
			taskName.endsWith(":publishJvmToMavenLocal") ||
			taskName.endsWith(":publishToMavenLocal") ||
			taskName.endsWith("PublicationToMavenLocal")
	}
