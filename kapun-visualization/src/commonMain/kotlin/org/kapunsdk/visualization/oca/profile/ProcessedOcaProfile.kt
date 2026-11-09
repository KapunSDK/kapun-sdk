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

import org.kapunsdk.visualization.oca.model.content.AttributeName
import org.kapunsdk.visualization.oca.model.content.SAID
import org.kapunsdk.visualization.oca.processing.ProcessedAttribute

/** A credential processed with an [OcaProfileBundleJson], in display order and localized. */
data class ProcessedOcaProfile(
    /** From the root's meta overlay. */
    val name: String?,
    val description: String?,
    val issuerName: String?,
    /** From the root's branding overlay. */
    val logo: String?,
    val primaryBackgroundColor: String?,
    /** The root capture base's attributes. */
    val root: ProcessedOcaNode.Group,
)

sealed interface ProcessedOcaNode {
    val attributeName: AttributeName
    val label: String

    /** A plain attribute. */
    data class Attribute(
        val attribute: ProcessedAttribute,
    ) : ProcessedOcaNode {
        override val attributeName get() = attribute.attributeName
        override val label get() = attribute.label ?: attribute.attributeName
    }

    /** A referenced capture base (`refs:<digest>`), or one element of a [GroupList]. */
    data class Group(
        override val attributeName: AttributeName,
        override val label: String,
        val captureBase: SAID,
        val children: List<ProcessedOcaNode>,
    ) : ProcessedOcaNode {
        /** The direct child attribute named [name], if any. */
        fun attribute(name: AttributeName) =
            children.filterIsInstance<Attribute>().firstOrNull { it.attributeName == name }?.attribute
    }

    /** A list of referenced capture bases (`Array[refs:<digest>]`), one [Group] per element of the credential's array. */
    data class GroupList(
        override val attributeName: AttributeName,
        override val label: String,
        val captureBase: SAID,
        val items: List<Group>,
    ) : ProcessedOcaNode
}
