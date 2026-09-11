package org.kapunsdk.trust.framework.oidcfederation

import org.kapunsdk.trust.framework.OidfTrustAnchorProvider
import uniffi.kapun_trust_rust.TrustAnchor

private val DEFAULT_TRUST_ANCHORS: List<String> = listOf(
    """{"kty":"EC","crv":"P-256","x":"HlgP6Ce_023fhGJWnLdILu83u-Fudi4MBesi6drVe2M","y":"VM1E-9_iPeuv0HLh1OFFKdBUTUOv1nBOO--UDfzGGjY"}"""
);

class StaticOidfTrustAnchorProvider(
    // Cannonicalized JWKs (fields as ordered by josekit::jwk::to_public_key)
    private val trustAnchors: List<String> = DEFAULT_TRUST_ANCHORS
) : OidfTrustAnchorProvider {

    override fun isTrusted(cannonicalizedJWK: TrustAnchor): Boolean {
        return trustAnchors.contains(cannonicalizedJWK.key);
    }
}