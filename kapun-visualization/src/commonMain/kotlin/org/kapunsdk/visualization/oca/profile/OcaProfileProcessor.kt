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

import org.kapunsdk.util.locale.LocaleMatcher
import org.kapunsdk.visualization.oca.model.content.AttributeName
import org.kapunsdk.visualization.oca.model.content.AttributeType
import org.kapunsdk.visualization.oca.model.content.SAID
import org.kapunsdk.visualization.oca.model.overlay.Localized
import org.kapunsdk.visualization.oca.model.overlay.Overlay
import org.kapunsdk.visualization.oca.model.overlay.input.ConformanceOverlay
import org.kapunsdk.visualization.oca.model.overlay.input.EntryOverlay
import org.kapunsdk.visualization.oca.model.overlay.presentation.AriesBrandingOverlay
import org.kapunsdk.visualization.oca.model.overlay.presentation.OrderOverlay
import org.kapunsdk.visualization.oca.model.overlay.semantic.FormatOverlay
import org.kapunsdk.visualization.oca.model.overlay.semantic.InformationOverlay
import org.kapunsdk.visualization.oca.model.overlay.semantic.LabelOverlay
import org.kapunsdk.visualization.oca.model.overlay.semantic.MetaOverlay
import org.kapunsdk.visualization.oca.model.overlay.semantic.StandardOverlay
import org.kapunsdk.visualization.oca.model.overlay.transformation.DataSourceOverlay
import org.kapunsdk.visualization.oca.processing.AttributeValueParser
import org.kapunsdk.visualization.oca.processing.ProcessedAttribute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/**
 * Processes a credential [payload] (the disclosed claims as JSON) with a multi capture base [bundle]:
 * starting at the root capture base, every attribute becomes a [ProcessedOcaNode] in the order of the order
 * overlay, with its localized label and its value, located by the data source overlay and typed by the
 * capture base and format overlay.
 *
 * Inside an element of an `Array[refs:…]` attribute, the first `null` in a data source path selects that
 * element. Labels may contain `{{refs:<digest>:<attribute>}}` (and `{{refs:<digest>:<attribute>.join('<separator>')}}`),
 * which are filled with that attribute's value(s).
 */
class OcaProfileProcessor(
	private val userLanguage: String,
	private val payload: JsonElement,
	private val bundle: OcaProfileBundleJson,
	val isBundleValid: Boolean = bundle.verifyIntegrity(),
) {
	constructor(userLanguage: String, payload: String, bundle: OcaProfileBundleJson) :
		this(userLanguage, Json.parseToJsonElement(payload), bundle)

	fun process(): ProcessedOcaProfile? {
		val root = bundle.rootDigest ?: return null
		val meta = overlay<MetaOverlay>(root)
		val branding = overlay<AriesBrandingOverlay>(root)
		return ProcessedOcaProfile(
			name = meta?.name,
			description = meta?.description,
			issuerName = meta?.issuerName,
			logo = branding?.logo,
			primaryBackgroundColor = branding?.primaryBackgroundColor,
			root = group(attributeName = "", label = meta?.name.orEmpty(), captureBase = root, indices = emptyList()),
		)
	}

	private fun group(attributeName: AttributeName, label: String, captureBase: SAID, indices: List<Int>): ProcessedOcaNode.Group {
		val attributes = bundle.captureBases[captureBase]?.attributes.orEmpty()
		val order = overlay<OrderOverlay>(captureBase)
		val sorted = attributes.keys.withIndex()
			.sortedWith(compareBy({ order?.getOrder(it.value) ?: Int.MAX_VALUE }, { it.index }))
			.map { it.value }
		return ProcessedOcaNode.Group(
			attributeName = attributeName,
			label = label,
			captureBase = captureBase,
			children = sorted.mapNotNull { node(captureBase, it, attributes.getValue(it), indices) },
		)
	}

	private fun node(captureBase: SAID, name: AttributeName, type: AttributeType, indices: List<Int>): ProcessedOcaNode? {
		val labelTemplate = overlay<LabelOverlay>(captureBase)?.getLabel(name) ?: name
		val reference = bundle.reference(captureBase, name)
		return when {
			reference == null -> ProcessedOcaNode.Attribute(attribute(captureBase, name, type, labelTemplate, indices))
			!reference.isArray -> group(name, interpolate(labelTemplate, indices), reference.digest, indices)
			else -> {
				val digest = reference.digest
				val count = elementCount(captureBase, name, digest, indices)
				ProcessedOcaNode.GroupList(
					attributeName = name,
					label = interpolate(labelTemplate, indices),
					captureBase = digest,
					items = (0 until count).map { index ->
						group(name, interpolate(labelTemplate, indices + index), digest, indices + index)
					},
				)
			}
		}
	}

	private fun attribute(captureBase: SAID, name: AttributeName, type: AttributeType, label: String, indices: List<Int>): ProcessedAttribute {
		val format = overlay<FormatOverlay>(captureBase)?.getFormat(name)
		val raw = resolve(captureBase, name, indices)?.toRawString()
		val entry = raw?.let { overlay<EntryOverlay>(captureBase)?.getEntry(name, it) }
		return ProcessedAttribute(
			attributeName = name,
			attributeType = type,
			attributeValue = raw?.let { AttributeValueParser.parse(entry ?: it, if (entry != null) AttributeType.Text else type, format) },
			label = interpolate(label, indices),
			information = overlay<InformationOverlay>(captureBase)?.getInformation(name),
			standard = overlay<StandardOverlay>(captureBase)?.getStandard(name),
			isMandatory = overlay<ConformanceOverlay>(captureBase)?.isMandatory(name) ?: false,
			isFlagged = name in bundle.captureBases[captureBase]?.flaggedAttributes.orEmpty(),
		)
	}

	/** How many elements an `Array[refs:…]` attribute has: from its own source, else from its elements' sources. */
	private fun elementCount(captureBase: SAID, name: AttributeName, elementCaptureBase: SAID, indices: List<Int>): Int {
		(resolve(captureBase, name, indices) as? JsonArray)?.let { return it.size }
		val elementPath = overlay<DataSourceOverlay>(elementCaptureBase)?.attributeSources?.values?.firstOrNull() ?: return 0
		val wildcard = elementPath.withIndex().filter { it.value is JsonNull }.getOrNull(indices.size)?.index ?: return 0
		return (resolvePath(elementPath.take(wildcard), indices) as? JsonArray)?.size ?: 0
	}

	/** The value of [name] in [captureBase]; a path with more wildcards than [indices] gives a [JsonArray] of all matches. */
	private fun resolve(captureBase: SAID, name: AttributeName, indices: List<Int>): JsonElement? {
		val path = overlay<DataSourceOverlay>(captureBase)?.getSource(name)
			?: if (captureBase == bundle.rootDigest) listOf(JsonPrimitive(name)) else return null
		return resolvePath(path, indices)
	}

	private fun resolvePath(path: List<JsonElement>, indices: List<Int>): JsonElement? {
		var remainingIndices = indices
		var current: List<JsonElement> = listOf(payload)
		var collect = false
		for (part in path) {
			current = current.flatMap { element ->
				when {
					part is JsonNull && element is JsonArray -> {
						val index = remainingIndices.firstOrNull()
						if (index != null && !collect) listOfNotNull(element.getOrNull(index)) else element.also { collect = true }
					}
					part is JsonPrimitive && part.isString && element is JsonObject -> listOfNotNull(element[part.content])
					part is JsonPrimitive && part.intOrNull != null && element is JsonArray -> listOfNotNull(element.getOrNull(part.intOrNull!!))
					else -> emptyList()
				}
			}
			if (part is JsonNull && remainingIndices.isNotEmpty() && !collect) remainingIndices = remainingIndices.drop(1)
		}
		return when {
			current.isEmpty() -> null
			collect -> JsonArray(current)
			else -> current.single()
		}
	}

	/** Fills `{{refs:<digest>:<attribute>}}` and `{{refs:<digest>:<attribute>.join('<separator>')}}` placeholders. */
	private fun interpolate(template: String, indices: List<Int>): String = PLACEHOLDER.replace(template) { match ->
		val (digest, name, separator) = match.destructured
		when (val value = resolve(digest, name, indices)) {
			is JsonArray -> value.mapNotNull { it.toRawString() }.joinToString(separator.ifEmpty { DEFAULT_SEPARATOR })
			else -> value?.toRawString().orEmpty()
		}
	}

	private fun JsonElement.toRawString(): String? = when (this) {
		is JsonNull -> null
		is JsonPrimitive -> contentOrNull
		else -> toString()
	}

	/**
	 * Prefers the overlay in the user's language (e.g. \`de-CH\` or \`de\` for \`de-CH\`), then one in the same language
	 * with another region (\`en-GB\` for \`en-US\`), otherwise the first overlay of that type.
	 */
	private inline fun <reified T : Overlay> overlay(captureBase: SAID): T? {
		val candidates = bundle.overlaysOf(captureBase).filterIsInstance<T>()
		return candidates.firstOrNull { it !is Localized || it.matches(userLanguage) }
			?: candidates.firstOrNull { it is Localized && LocaleMatcher.matches(it.language, userLanguage, allowLanguageOnlyMatch = true) }
			?: candidates.firstOrNull()
	}

	private companion object {
		val PLACEHOLDER = Regex("""\{\{refs:([^:}]+):([A-Za-z0-9_]+)(?:\.join\('([^']*)'\))?\}\}""")
		const val DEFAULT_SEPARATOR = ", "
	}
}
