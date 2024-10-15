use bs58;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::sha2::{Digest, Sha256};
use k256::EncodedPoint;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Scalar, Secp256k1, U256,
};
use near_sdk::AccountId;
use ripemd::Ripemd160;
use sha3::Sha3_256;

// Types
pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    /// When the user can't directly select the value, this will always work
    /// Use cases are things that we know have been hashed
    fn from_non_biased(hash: [u8; 32]) -> Self {
        // This should never happen.
        // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
        // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
        Scalar::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
    }
}

// Constant prefix that ensures epsilon derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_epsilon(predecessor_id: &AccountId, path: &str) -> Scalar {
    let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

const ROOT_PUBLIC_KEY: &str = "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3";
pub struct DerivedAddress {
    pub address: String,
    pub public_key: PublicKey,
}

pub fn get_derived_address(predecessor_id: &AccountId, path: &str) -> DerivedAddress {
    let epsilon = derive_epsilon(predecessor_id, path);
    let public_key = convert_string_to_public_key(ROOT_PUBLIC_KEY).unwrap();
    let derived_public_key = derive_key(public_key, epsilon);
    let address = public_key_to_btc_address(derived_public_key, "testnet");
    DerivedAddress {
        address,
        public_key: derived_public_key,
    }
}

fn convert_string_to_public_key(encoded: &str) -> Result<PublicKey, String> {
    let base58_part = encoded.strip_prefix("secp256k1:").ok_or("Invalid prefix")?;

    let mut decoded_bytes = bs58::decode(base58_part)
        .into_vec()
        .map_err(|_| "Base58 decoding failed")?;

    if decoded_bytes.len() != 64 {
        return Err(format!(
            "Invalid public key length: expected 64, got {}",
            decoded_bytes.len()
        ));
    }

    decoded_bytes.insert(0, 0x04);

    let public_key = EncodedPoint::from_bytes(&decoded_bytes).unwrap();

    let public_key = AffinePoint::from_encoded_point(&public_key).unwrap();

    Ok(public_key)
}

fn public_key_to_hex(public_key: AffinePoint) -> String {
    let encoded_point = public_key.to_encoded_point(false);
    let encoded_point_bytes = encoded_point.as_bytes();

    hex::encode(encoded_point_bytes)
}

fn public_key_to_btc_address(public_key: AffinePoint, network: &str) -> String {
    let encoded_point = public_key.to_encoded_point(false);
    let public_key_bytes = encoded_point.as_bytes();

    let sha256_hash = Sha256::digest(public_key_bytes);

    let ripemd160_hash = Ripemd160::digest(&sha256_hash);

    let network_byte = if network == "bitcoin" { 0x00 } else { 0x6f };
    let mut address_bytes = vec![network_byte];
    address_bytes.extend_from_slice(&ripemd160_hash);

    base58check_encode(&address_bytes)
}

fn base58check_encode(data: &[u8]) -> String {
    // Perform a double SHA-256 hash on the data
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);

    // Take the first 4 bytes of the second hash as the checksum
    let checksum = &hash2[..4];

    // Append the checksum to the original data
    let mut data_with_checksum = Vec::from(data);
    data_with_checksum.extend_from_slice(checksum);

    // Encode the data with checksum using Base58
    bs58::encode(data_with_checksum).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_epsilon() {
        let predecessor_id = "omnitester.testnet".parse().unwrap();
        let path = "bitcoin-1";

        let epsilon = derive_epsilon(&predecessor_id, path);

        let public_key = convert_string_to_public_key("secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3").unwrap();

        let derived_public_key = derive_key(public_key, epsilon);

        let derived_public_key_hex = public_key_to_hex(derived_public_key);

        let btc_address = public_key_to_btc_address(derived_public_key, "testnet");

        assert_eq!(btc_address, "mk65535111111111111111111111111111111111111");
        assert_eq!(derived_public_key_hex, "04458506f68f2435939e686b67624d4ea03714a49f6c57548b6c9a3e93c96edb2977781d46bc27b12013c758e068025c64b31c8378bfa30d4d4f0fa8a6e4e56a6");
    }
}
