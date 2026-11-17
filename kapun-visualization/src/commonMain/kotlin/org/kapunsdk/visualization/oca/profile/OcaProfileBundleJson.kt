/* Copyright 2026 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */
package org.kapunsdk.visualization.oca.profile

import org.kapunsdk.util.log.Logger
import org.kapunsdk.visualization.oca.model.CaptureBase
import org.kapunsdk.visualization.oca.model.computeCesrEncodedDigest
import org.kapunsdk.visualization.oca.model.content.AttributeType
import org.kapunsdk.visualization.oca.model.content.AttributeName
import org.kapunsdk.visualization.oca.model.content.SAID
import org.kapunsdk.visualization.oca.model.overlay.Overlay
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.serializer

/**
 * An OCA bundle with several capture bases, as used by the Swiss VC profile (`profile_version`
 * `swiss-profile-vc:1.0.0`): one root capture base whose attributes can reference other capture bases
 * (`refs:<digest>`, or `Array[refs:<digest>]` for a list of them), and overlays that each belong to one
 * capture base. Values are located in the credential by `data_source` overlays.
 *
 * The capture bases and overlays are kept as they appear in the JSON, so their SAIDs can be verified.
 * Overlays of types this library doesn't know are skipped.
 */
@Serializable
data class OcaProfileBundleJson(
	@SerialName("profile_version") val profileVersion: String? = null,
	@SerialName("capture_bases") val captureBasesJson: List<JsonObject>,
	@SerialName("overlays") val overlaysJson: List<JsonObject>,
) {

	@Transient
	val captureBases: Map<SAID, CaptureBase> = captureBasesJson
		.map { json.decodeFromJsonElement(CaptureBase.serializer(), it) }
		.associateBy { it.digest }

	@Transient
	val overlays: List<Overlay> = overlaysJson.mapNotNull { overlay ->
		runCatching { json.decodeFromJsonElement(serializer<Overlay>(), overlay) }
			.onFailure { Logger.debug("Skipping OCA overlay ${overlay["type"]}: ${it.message}") }
			.getOrNull()
	}

	/**
	 * The attributes that reference another capture base, per capture base. [AttributeType] has no type for
	 * references (`refs:<digest>` decodes as [AttributeType.Unknown]), so they are read from the JSON.
	 */
	@Transient
	val references: Map<SAID, Map<AttributeName, CaptureBaseReference>> = captureBasesJson.associate { raw ->
		val digest = raw["digest"]?.jsonPrimitive?.contentOrNull.orEmpty()
		val attributes = (raw["attributes"] as? JsonObject).orEmpty()
		digest to attributes.mapNotNull { (name, type) ->
			(type as? JsonPrimitive)?.contentOrNull?.let(CaptureBaseReference::parse)?.let { name to it }
		}.toMap()
	}

	/** The capture base no other capture base refers to. */
	@Transient
	val rootDigest: SAID? = run {
		val referenced = references.values.flatMap { it.values }.map { it.digest }.toSet()
		captureBases.keys.firstOrNull { it !in referenced } ?: captureBases.keys.firstOrNull()
	}

	fun reference(captureBase: SAID, attributeName: AttributeName): CaptureBaseReference? = references[captureBase]?.get(attributeName)

	fun overlaysOf(captureBase: SAID): List<Overlay> = overlays.filter { it.captureBase == captureBase }

	/**
	 * Checks that every capture base matches its SAID, that every reference points to a capture base of
	 * this bundle, and that every overlay belongs to one. Overlays only carry a digest in some bundles;
	 * when they do, it's verified too.
	 */
	fun verifyIntegrity(): Boolean {
		if (captureBases.isEmpty() || captureBases.size != captureBasesJson.size) return false
		val captureBasesValid = captureBasesJson.all { raw ->
			val digest = raw["digest"]?.jsonPrimitive?.contentOrNull ?: return@all false
			computeCesrEncodedDigest(raw, digest.first().toString()) == digest
		}
		val referencesValid = references.values.flatMap { it.values }.all { it.digest in captureBases }
		val overlaysValid = overlaysJson.all { raw ->
			val captureBase = raw["capture_base"]?.jsonPrimitive?.contentOrNull
			val digest = raw["digest"]?.jsonPrimitive?.contentOrNull
			captureBase in captureBases && (digest == null || computeCesrEncodedDigest(raw, digest.first().toString()) == digest)
		}
		return captureBasesValid && referencesValid && overlaysValid
	}

	companion object {
		private val json = Json {
			ignoreUnknownKeys = true
			encodeDefaults = true
		}

		fun fromJson(bundle: String): OcaProfileBundleJson = json.decodeFromString(serializer(), bundle)
	}
}

/** An attribute of type `refs:<digest>` ([isArray] false) or `Array[refs:<digest>]` ([isArray] true). */
data class CaptureBaseReference(val digest: String, val isArray: Boolean) {
	companion object {
		private val REFERENCE = Regex("""^Array\[refs:([^\]]+)]$|^refs:(.+)$""")

		fun parse(type: String): CaptureBaseReference? = REFERENCE.matchEntire(type)?.let { match ->
			val (arrayDigest, digest) = match.destructured
			if (arrayDigest.isNotEmpty()) CaptureBaseReference(arrayDigest, isArray = true) else CaptureBaseReference(digest, isArray = false)
		}
	}
}
