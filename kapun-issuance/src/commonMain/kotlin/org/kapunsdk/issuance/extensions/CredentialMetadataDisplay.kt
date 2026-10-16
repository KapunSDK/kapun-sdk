/*
 * Copyright 2025 Ubique Innovation AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.kapunsdk.issuance.extensions

import org.kapunsdk.issuance.metadata.data.Display
import org.kapunsdk.util.locale.LocaleMatcher

/**
 * Returns the label matching the given locale, falling back to english and then to any available label.
 */
fun List<Display>?.getLocalizedLabel(locale: String): String? {
	if (this == null) return null
	getLabelForLocale(locale)?.let { return it }

	firstOrNull { it.locale.equals("en", ignoreCase = true) && !it.name.isNullOrBlank() }?.name?.let { return it }

	return firstOrNull { !it.name.isNullOrBlank() }?.name
}

/**
 * Returns the label matching the given locale without any fallback to other languages.
 * An exact match is preferred over a match of the language only (e.g. "de-DE" for "de-CH").
 */
fun List<Display>?.getLabelForLocale(locale: String): String? {
	if (this == null) return null
	val labels = filter { it.locale != null && !it.name.isNullOrBlank() }
	return labels.firstOrNull { it.locale.equals(locale, ignoreCase = true) }?.name
		?: labels.firstOrNull { LocaleMatcher.matches(it.locale!!, locale, allowLanguageOnlyMatch = true) }?.name
}
