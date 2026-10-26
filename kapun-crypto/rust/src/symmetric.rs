use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;

#[derive(Debug, uniffi::Error)]
pub enum SymmetricError {
    InvalidOutputLength,
    RandomGenerationFailed,
}

impl std::fmt::Display for SymmetricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidOutputLength => {
                "HKDF-SHA256 output length is invalid"
            }
            Self::RandomGenerationFailed => "Failed to generate secure random bytes",
        })
    }
}

impl std::error::Error for SymmetricError {}

#[uniffi::export]
pub fn secure_random_bytes(length: u32) -> Result<Vec<u8>, SymmetricError> {
    let mut bytes = vec![0; length as usize];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SymmetricError::RandomGenerationFailed)?;
    Ok(bytes)
}

#[uniffi::export]
pub fn hkdf_sha256(
    key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: u32,
) -> Result<Vec<u8>, SymmetricError> {
    if output_length == 0 || output_length > 255 * 32 {
        return Err(SymmetricError::InvalidOutputLength);
    }
    let mut output = vec![0; output_length as usize];
    Hkdf::<Sha256>::new(Some(salt), key_material)
        .expand(info, &mut output)
        .map_err(|_| SymmetricError::InvalidOutputLength)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_test_case() {
        let output = hkdf_sha256(
            &[0x0b; 22],
            &(0x00..=0x0c).collect::<Vec<_>>(),
            &(0xf0..=0xf9).collect::<Vec<_>>(),
            42,
        )
        .unwrap();
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(output, expected);
    }

    #[test]
    fn generates_random_bytes() {
        assert_eq!(secure_random_bytes(0).unwrap(), Vec::<u8>::new());
        let first = secure_random_bytes(32).unwrap();
        let second = secure_random_bytes(32).unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert_ne!(first, second);
    }
}
