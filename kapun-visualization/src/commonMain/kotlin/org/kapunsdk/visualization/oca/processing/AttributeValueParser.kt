/* Copyright 2025 Ubique Innovation AG

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

package org.kapunsdk.visualization.oca.processing

import org.kapunsdk.util.extensions.fromSecondsOrMillis
import org.kapunsdk.util.log.Logger
import org.kapunsdk.visualization.extensions.isPng
import org.kapunsdk.visualization.extensions.tryDecodeBase64
import org.kapunsdk.visualization.oca.model.content.AttributeType
import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.format.FormatStringsInDatetimeFormats
import kotlinx.datetime.format.byUnicodePattern
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Turns the raw string value of an attribute into an [AttributeValue], based on its [AttributeType] and format.
 * Shared by [OcaProcessor] and [org.kapunsdk.visualization.oca.profile.OcaProfileProcessor].
 */
@OptIn(ExperimentalTime::class)
internal object AttributeValueParser {

	@OptIn(ExperimentalEncodingApi::class)
	fun parse(rawValue: String, attributeType: AttributeType, format: String?): AttributeValue<*> {
		return when (attributeType) {
			is AttributeType.Array -> {
				when(attributeType.contentType) {
					is AttributeType.Binary -> {
						val bytes = rawValue.trim('[', ']').split(",").map {
							val ubyte = runCatching { it.trim().toUByte().toByte() }
							if(ubyte.isSuccess) {
								ubyte.getOrThrow()
							} else {
								it.trim().toByte()
							}
						}.toByteArray()
						AttributeValue.Image(bytes, format)
					}
					else -> {
						val values = rawValue.trim('[', ']').split(",").map { AttributeValue.Text(it) }
						AttributeValue.Array(values)
					}
				}
			}
			AttributeType.Binary -> {
				// The format of the attribute is specified (it is an image), try decoding it and return an image with bytes
				when {
					format?.startsWith("image/") == true -> {
						rawValue.tryDecodeBase64()?.let {
							AttributeValue.Image(it, format)
						} ?: AttributeValue.Raw(rawValue, format)
					}
					// the format is specified, but it is not a picture, return the values as is
					format != null -> AttributeValue.Raw(rawValue, format)
					else -> {
						// it is a binary attribute. We don't know the format, as such we try to "guess" the format
						// by looking at the content. We handle data urls, containing base64 erncoded binary data, and
						// base64 encoded png data.
						val dataUrlScheme = "data:(.*);base64,(.*)".toRegex()
						val matches = dataUrlScheme.matchEntire(rawValue)?.groupValues
						val mediaType = matches?.getOrNull(1)
						val data = matches?.getOrNull(2)
						// iVBOR is the starting string of Base64 encoded PNG images.
						val realData = data ?: if (rawValue.isPng()) { rawValue } else { null }
						realData.tryDecodeBase64()?.let { AttributeValue.Image(it, format) } ?: AttributeValue.Raw(rawValue, format)
					}
				}
			}
			AttributeType.Boolean -> AttributeValue.Bool(rawValue.toBoolean())
			AttributeType.DateTime -> {
				if (format.equals("timestamp", ignoreCase = true)) {
					val instant = Instant.fromSecondsOrMillis(rawValue.toLong())
					AttributeValue.Timestamp(instant)
				} else if (format.equals("instant", ignoreCase = true)) {
					val instant = runCatching {  Instant.parse(rawValue) }.getOrNull()
					instant?.let { AttributeValue.Timestamp(instant) } ?: AttributeValue.Raw(rawValue)
				} else {
					val sanitizedFormat = (format ?: "YYYY-MM-DDTHH:mm:ssZ").sanitizeDateTimePattern()
					parseDateTime(rawValue, sanitizedFormat)?.let {
						AttributeValue.DateTime(it)
					} ?: parseDate(rawValue, sanitizedFormat)?.let {
						AttributeValue.Date(it)
					} ?: AttributeValue.Raw(rawValue)
				}
			}
			AttributeType.Numeric -> AttributeValue.Text(rawValue) // TODO Parse to Double/Long or leave as String?
			AttributeType.Reference -> TODO("Reference not yet implemented")
			AttributeType.Text -> {
				val linkRegex = """Link\[(.+)]""".toRegex()
				val match = format?.let { linkRegex.matchEntire(it) }

				if (match != null) {
					val (typeStr) = match.destructured
					val linkType = try {
						AttributeValue.LinkType.valueOf(typeStr)
					} catch (e: IllegalArgumentException) {
						Logger.error("Unknown LinkType: $typeStr in value: $rawValue")
						null
					}

					if (linkType != null) {
						AttributeValue.Link(value = rawValue, linkType = linkType)
					} else {
						AttributeValue.Text(rawValue)
					}
				} else {
					AttributeValue.Text(rawValue)
				}
			}
			AttributeType.Unknown -> AttributeValue.Raw(rawValue)
		}
	}

	private fun String.sanitizeDateTimePattern(): String {
		return this
			.replace("Y", "y") // "Year of the week" is not supported by KotlinX DateTime
			.replace("D", "d") // "Day in year" is not supported by KotlinX DateTime
	}

	@OptIn(FormatStringsInDatetimeFormats::class)
	private fun parseDateTime(rawValue: String, format: String): LocalDateTime? {
		return try {
			val formatter = LocalDateTime.Format { byUnicodePattern(format) }
			LocalDateTime.parse(rawValue, formatter)
		} catch (e: Exception) {
			null
		}
	}

	@OptIn(FormatStringsInDatetimeFormats::class)
	private fun parseDate(rawValue: String, format: String): LocalDate? {
		return try {
			val formatter = LocalDate.Format { byUnicodePattern(format) }
			LocalDate.parse(rawValue, formatter)
		} catch (e: Exception) {
			null
		}
	}
}
