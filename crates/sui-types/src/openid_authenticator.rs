// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    base_types::SuiAddress,
    committee::EpochId,
    crypto::{Signature, SignatureScheme, SuiSignature},
    error::SuiError,
    signature::AuthenticatorTrait,
};
use fastcrypto::rsa::Base64UrlUnpadded;
use fastcrypto::rsa::Encoding as OtherEncoding;
use fastcrypto::rsa::RSAPublicKey;
use fastcrypto::rsa::RSASignature;
use fastcrypto_zkp::bn254::poseidon::calculate_merklized_hash;
use fastcrypto_zkp::bn254::{api::CanonicalSerialize, poseidon::bytearray_to_bits};
use fastcrypto_zkp::bn254::{
    api::{
        serialize_proof_from_file, serialize_public_inputs_from_file,
        serialize_verifying_key_from_file, Bn254Fr,
    },
    poseidon::PoseidonWrapper,
};
use num_bigint::BigInt;
use once_cell::sync::OnceCell;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_crypto::intent::Intent;
use shared_crypto::intent::{IntentMessage, IntentScope};
use std::hash::Hasher;
use std::{fs::File, hash::Hash, str::FromStr};

#[cfg(test)]
#[path = "unit_tests/openid_authenticator_tests.rs"]
mod openid_authenticator_tests;

/// An open id authenticator with all the necessary fields.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct OpenIdAuthenticator {
    vk: SerializedVerifyingKey,
    proof_points: ProofPoints,
    public_inputs: PublicInputs,
    aux_inputs: AuxInputs,
    user_signature: Signature,
    bulletin_signature: Signature,
    bulletin: Vec<OAuthProviderContent>,
    #[serde(skip)]
    pub bytes: OnceCell<Vec<u8>>,
}

impl OpenIdAuthenticator {
    /// Create a new [struct OpenIdAuthenticator] with necessary fields.
    pub fn new(
        vk: SerializedVerifyingKey,
        proof_points: ProofPoints,
        public_inputs: PublicInputs,
        aux_inputs: AuxInputs,
        user_signature: Signature,
        bulletin_signature: Signature,
        bulletin: Vec<OAuthProviderContent>,
    ) -> Self {
        Self {
            vk,
            proof_points,
            public_inputs,
            aux_inputs,
            user_signature,
            bulletin_signature,
            bulletin,
            bytes: OnceCell::new(),
        }
    }

    /// Get the serialized format of the verifying key.
    pub fn get_vk(&self) -> &SerializedVerifyingKey {
        &self.vk
    }
}

/// Necessary trait for [struct SenderSignedData].
impl PartialEq for OpenIdAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.vk == other.vk
            && self.proof_points == other.proof_points
            && self.aux_inputs == other.aux_inputs
            && self.user_signature == other.user_signature
            && self.bulletin_signature == other.bulletin_signature
            && self.bulletin == other.bulletin
    }
}

/// Necessary trait for [struct SenderSignedData].
impl Eq for OpenIdAuthenticator {}

/// Necessary trait for [struct SenderSignedData].
impl Hash for OpenIdAuthenticator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

/// Prepared verifying key in serialized form.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct SerializedVerifyingKey {
    pub vk_gamma_abc_g1: Vec<u8>,
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
}

impl SerializedVerifyingKey {
    /// Parse the serialized verifying key from a file.
    pub fn from_fp(path: &str) -> Self {
        let v = serialize_verifying_key_from_file(path);
        let (a, b, c, d) = match (v.get(0), v.get(1), v.get(2), v.get(3)) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => panic!("Invalid verifying key file"),
        };
        Self {
            vk_gamma_abc_g1: a.clone(),
            alpha_g1_beta_g2: b.clone(),
            gamma_g2_neg_pc: c.clone(),
            delta_g2_neg_pc: d.clone(),
        }
    }
}

/// The public inputs containing the all_inputs_hash and its serialized form.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct PublicInputs {
    all_inputs_hash: String,  // Represented in a BigInt string.
    serialized_hash: Vec<u8>, // Represented the public inputs in canonical serialized form.
}

impl PublicInputs {
    /// Parse the public inputs from a file.
    pub fn from_fp(path: &str) -> Self {
        let inputs = serialize_public_inputs_from_file(path);
        let mut serialized_hash = Vec::new();
        for a in inputs.clone() {
            a.serialize_compressed(&mut serialized_hash).unwrap()
        }
        Self {
            all_inputs_hash: inputs[0].to_string(),
            serialized_hash,
        }
    }
}

/// The serialized bytes of the proof points.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct ProofPoints {
    bytes: Vec<u8>,
}

impl ProofPoints {
    /// Parse the proof points from a file.
    pub fn from_fp(path: &str) -> Self {
        Self {
            bytes: serialize_proof_from_file(path),
        }
    }
}

/// A structed of all parsed and validated values from the masked content bytes.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct ParsedMaskedContent {
    header: JWTHeader,
    iss: String,
    wallet_id: String,
    nonce: String,
    hash: String,
}

impl ParsedMaskedContent {
    /// Parse the masked content bytes into a [struct ParsedMaskedContent].
    /// Aux inputs (payload_start_index, payload_len, num_sha2_blocks) are
    /// are used for validation and parsing.
    pub fn new(
        masked_content: &[u8],
        payload_start_index: usize,
        payload_len: usize,
        num_sha2_blocks: usize,
    ) -> Result<Self, SuiError> {
        // Verify the bytes after 64 * num_sha2_blocks should be all 0s.
        if !masked_content[64 * num_sha2_blocks..]
            .iter()
            .all(|&x| x == 0)
        {
            return Err(SuiError::InvalidSignature {
                error: "Incorrect payload padding".to_string(),
            });
        }

        let masked_content_tmp = &masked_content[..64 * num_sha2_blocks];

        // Verify the byte at payload start index is indeed b'.'.
        if masked_content_tmp.get(payload_start_index - 1) != Some(&b'.') {
            return Err(SuiError::InvalidSignature {
                error: "Incorrect payload index for separator".to_string(),
            });
        }

        let header =
            parse_and_validate_header(masked_content_tmp.get(0..payload_start_index - 1).ok_or(
                SuiError::InvalidSignature {
                    error: "Invalid payload index to parse header".to_string(),
                },
            )?)?;

        // Parse the jwt length from the last 8 bytes of the masked content.
        let jwt_length_bytes = masked_content_tmp
            .get(masked_content_tmp.len() - 8..)
            .ok_or(SuiError::InvalidSignature {
                error: "Invalid last 8 bytes".to_string(),
            })?;
        let jwt_length = calculate_value_from_bytearray(jwt_length_bytes);

        // Verify the jwt length equals to 8*(payload_start_index + payload_len).
        if jwt_length != 8 * (payload_start_index + payload_len) {
            return Err(SuiError::InvalidSignature {
                error: "Incorrect jwt length".to_string(),
            });
        }

        // Parse sha2 pad into a bit array.
        let sha_2_pad = bytearray_to_bits(&masked_content_tmp[payload_start_index + payload_len..]);

        // Verify that the first bit of the bit array of sha2 pad is 1.
        if !sha_2_pad[0] {
            return Err(SuiError::InvalidSignature {
                error: "Incorrect sha2 padding".to_string(),
            });
        }

        // Verify the count of 0s in the sha2 pad bit array satifies the condition
        // with the jwt length.
        validate_zeros_count(&sha_2_pad, jwt_length)?;

        // Splits the masked payload into 3 parts (that reveals iss, aud, nonce respectively)
        // separated by a delimiter of "=" of any length.
        let (parts, indices) = find_parts_and_indices(
            &masked_content_tmp[payload_start_index..payload_start_index + payload_len],
        )?;

        Ok(Self {
            header,
            iss: find_value(parts[0], "{\"iss\":\"", "\"", indices[0])?,
            wallet_id: find_value(parts[1], ",\"aud\":\"", "\"", indices[1])?,
            nonce: find_value(parts[2], ",\"nonce\":\"", "\"", indices[2])?,
            hash: calculate_merklized_hash(masked_content_tmp),
        })
    }
}

/// Struct that contains all the OAuth provider information. A list of them can
/// be retrieved from the JWK endpoint (e.g. https://www.googleapis.com/oauth2/v3/certs)
/// and published on the bulletin along with a trusted party's signature.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OAuthProviderContent {
    iss: String,
    kty: String,
    kid: String,
    e: String,
    n: String,
    alg: String,
    wallet_id: String,
}

impl OAuthProviderContent {
    /// Create a new OAuthProviderContent with all given fields.
    pub fn new(
        iss: String,
        kty: String,
        kid: String,
        e: String,
        n: String,
        alg: String,
        wallet_id: String,
    ) -> Self {
        Self {
            iss,
            kty,
            kid,
            e,
            n,
            alg,
            wallet_id,
        }
    }
}

/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct JWTHeader {
    alg: String,
    kid: String,
    typ: String,
}

/// A parsed result of all aux inputs where the masked content is parsed with
/// all necessary fields.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct AuxInputs {
    masked_content: ParsedMaskedContent,
    jwt_signature: Vec<u8>,
    jwt_sha2_hash: Vec<String>, // Represented in 2 BigInt strings.
    payload_start_index: usize,
    payload_len: usize,
    eph_public_key: Vec<String>, // Represented in 2 BigInt strings.
    max_epoch: EpochId,
    num_sha2_blocks: usize,
}

/// A helper struct that helps to read the aux input from JSON format from file.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct AuxInputsReader {
    masked_content: Vec<u8>,
    jwt_signature: String,
    jwt_sha2_hash: Vec<String>,
    payload_start_index: usize,
    payload_len: usize,
    eph_public_key: Vec<String>,
    max_epoch: EpochId,
    num_sha2_blocks: usize,
}

impl AuxInputs {
    /// Parse and validate all aux inputs from a file.
    pub fn from_fp(path: &str) -> Result<Self, SuiError> {
        let file = File::open(path).map_err(|_| SuiError::InvalidSignature {
            error: "Cannot open file".to_string(),
        })?;
        let reader = std::io::BufReader::new(file);
        let inputs: AuxInputsReader =
            serde_json::from_reader(reader).map_err(|_| SuiError::InvalidSignature {
                error: "Cannot read aux inputs".to_string(),
            })?;
        Ok(Self {
            jwt_signature: Base64UrlUnpadded::decode_vec(&inputs.jwt_signature).map_err(|_| {
                SuiError::InvalidSignature {
                    error: "Cannot parse jwt signature".to_string(),
                }
            })?,
            masked_content: ParsedMaskedContent::new(
                &inputs.masked_content,
                inputs.payload_start_index,
                inputs.payload_len,
                inputs.num_sha2_blocks,
            )?,
            jwt_sha2_hash: inputs.jwt_sha2_hash,
            payload_start_index: inputs.payload_start_index,
            payload_len: inputs.payload_len,
            eph_public_key: inputs.eph_public_key,
            max_epoch: inputs.max_epoch,
            num_sha2_blocks: inputs.num_sha2_blocks,
        })
    }

    /// Get the jwt hash in byte array format.
    pub fn get_jwt_hash(&self) -> Vec<u8> {
        self.jwt_sha2_hash
            .iter()
            .flat_map(|x| big_int_str_to_hash(x))
            .collect()
    }

    /// Get the ephemeral pubkey in byte array format.
    pub fn get_eph_pub_key(&self) -> Vec<u8> {
        self.eph_public_key
            .iter()
            .flat_map(|x| big_int_str_to_hash(x))
            .collect()
    }
}

impl AuthenticatorTrait for OpenIdAuthenticator {
    /// Verify an intent message of a transaction with an OpenID authenticator.
    fn verify_secure_generic<T>(
        &self,
        intent_msg: &IntentMessage<T>,
        author: SuiAddress,
        epoch: Option<EpochId>,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        // Verify the author of the transaction is indeed the hash of the verifying key.
        if author != (&self.vk).into() {
            return Err(SuiError::InvalidAuthenticator);
        }

        let aux_inputs = &self.aux_inputs;
        let masked_content = &aux_inputs.masked_content;

        // Verify the max epoch in aux inputs is within the current epoch.
        if aux_inputs.max_epoch < epoch.unwrap_or(0) {
            return Err(SuiError::InvalidSignature {
                error: "Invalid epoch".to_string(),
            });
        }

        // Calculates the hash of all inputs equals to the one in public inputs.
        if calculate_all_inputs_hash_from_aux_inputs(aux_inputs)
            != self.public_inputs.all_inputs_hash
        {
            return Err(SuiError::InvalidSignature {
                error: "Invalid all inputs hash".to_string(),
            });
        }

        // Verify the provided bulletin signature indeed commits to the provided
        // bulletin content containing a list of valid OAuth provider contents, e.g.
        // https://www.googleapis.com/oauth2/v3/certs.
        if self
            .bulletin_signature
            .verify_secure(
                &IntentMessage::new(
                    Intent::sui_app(IntentScope::PersonalMessage),
                    self.bulletin.clone(),
                ),
                // foundation address, harded coded for now.
                SuiAddress::from_str(
                    "0x73a6b3c33e2d63383de5c6786cbaca231ff789f4c853af6d54cb883d8780adc0",
                )
                .unwrap(),
            )
            .is_err()
        {
            return Err(SuiError::InvalidSignature {
                error: "Failed to verify bulletin signature".to_string(),
            });
        }

        // Verify the JWT signature against one of OAuth provider public keys in the bulletin.
        let sig = RSASignature::from_bytes(&aux_inputs.jwt_signature).map_err(|_| {
            SuiError::InvalidSignature {
                error: "Invalid JWT signature".to_string(),
            }
        })?;

        // Since more than one JWKs are available in the bulletin, iterate and find the one with
        // matching kid, iss, and wallet_id (aud) and verify the signature against it.
        let mut verified = false;
        for info in self.bulletin.iter() {
            if info.kid == masked_content.header.kid
                && info.iss == masked_content.iss
                && info.wallet_id == masked_content.wallet_id
            {
                let pk = RSAPublicKey::from_raw_components(
                    &Base64UrlUnpadded::decode_vec(&info.n).map_err(|_| {
                        SuiError::InvalidSignature {
                            error: "Invalid OAuth provider pubkey n".to_string(),
                        }
                    })?,
                    &Base64UrlUnpadded::decode_vec(&info.e).map_err(|_| {
                        SuiError::InvalidSignature {
                            error: "Invalid OAuth provider pubkey e".to_string(),
                        }
                    })?,
                )
                .map_err(|_| SuiError::InvalidSignature {
                    error: "Invalid RSA raw components".to_string(),
                })?;
                if pk
                    .verify_prehash(&self.aux_inputs.get_jwt_hash(), &sig)
                    .is_ok()
                {
                    verified = true;
                }
            }
        }

        if !verified {
            return Err(SuiError::InvalidSignature {
                error: "JWT signature verify failed".to_string(),
            });
        }

        // Ensure the ephemeral public key in the aux inputs matches the one in the
        // user signature.
        if self.aux_inputs.get_eph_pub_key() != self.user_signature.public_key_bytes() {
            return Err(SuiError::InvalidSignature {
                error: "Invalid ephemeral public_key".to_string(),
            });
        }

        // Verify the user signature over the intent message of the transaction data.
        if self
            .user_signature
            .verify_secure(intent_msg, author)
            .is_err()
        {
            return Err(SuiError::InvalidSignature {
                error: "User signature verify failed".to_string(),
            });
        }

        // Finally, verify the Groth16 proof, with the verifying key, public inputs
        // and proof points.
        match fastcrypto_zkp::bn254::api::verify_groth16_in_bytes(
            &self.vk.vk_gamma_abc_g1,
            &self.vk.alpha_g1_beta_g2,
            &self.vk.gamma_g2_neg_pc,
            &self.vk.delta_g2_neg_pc,
            &self.public_inputs.serialized_hash,
            &self.proof_points.bytes,
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(SuiError::InvalidSignature {
                error: "Groth16 proof verify failed".to_string(),
            }),
        }
    }
}

impl AsRef<[u8]> for OpenIdAuthenticator {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let as_bytes = bcs::to_bytes(self).expect("BCS serialization should not fail");
                let mut bytes = Vec::with_capacity(1 + as_bytes.len());
                bytes.push(SignatureScheme::OpenIdAuthenticator.flag());
                bytes.extend_from_slice(as_bytes.as_slice());
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

/// ----- Utility functions -----
///
/// Parse the ascii string from the input bytearray and split it by delimiter "=" of any
/// length. Return a list of the split parts and a list of start indices of each part.
pub fn find_parts_and_indices(input: &[u8]) -> Result<(Vec<&str>, Vec<usize>), SuiError> {
    let input_str = std::str::from_utf8(input).map_err(|_| SuiError::InvalidSignature {
        error: "Invalid masked content".to_string(),
    })?;
    let re = Regex::new("=+").expect("Regex string should be valid");

    let mut chunks = Vec::new();
    let mut indices = Vec::new();

    let mut start_idx = 0;

    for mat in re.find_iter(input_str) {
        let end_idx = mat.start();
        if start_idx < end_idx {
            chunks.push(&input_str[start_idx..end_idx]);
            indices.push(start_idx);
        }
        start_idx = mat.end();
    }

    if start_idx < input.len() {
        chunks.push(&input_str[start_idx..]);
        indices.push(start_idx);
    }
    Ok((chunks, indices))
}

/// Given a part in string, find the value between the prefix and suffix.
/// The index value is used to decide the number of '0' needed to pad to
/// make the parts an valid Base64 encoding.
pub fn find_value(
    part: &str,
    prefix: &str,
    suffix: &str,
    index: usize,
) -> Result<String, SuiError> {
    let prefix_padding = "0".repeat(index % 4);
    let suffix_padding = match part.len() % 4 {
        0 => "".to_string(),
        _ => "0".repeat(4 - part.len() % 4),
    };
    let padded_str = format!("{}{}{}", prefix_padding, part, suffix_padding);

    let decoded =
        Base64UrlUnpadded::decode_vec(&padded_str).map_err(|_| SuiError::InvalidSignature {
            error: "Invalid base64 encoded str".to_string(),
        })?;
    let ascii_string = std::str::from_utf8(&decoded).map_err(|_| SuiError::InvalidSignature {
        error: "Invalid ascii string".to_string(),
    })?;
    let start = ascii_string
        .find(prefix)
        .ok_or(SuiError::InvalidSignature {
            error: "Invalid parts prefix".to_string(),
        })?
        + prefix.len();
    let end = ascii_string[start..]
        .find(suffix)
        .ok_or(SuiError::InvalidSignature {
            error: "Invalid ascii suffix".to_string(),
        })?
        + start;
    Ok(ascii_string[start..end].to_string())
}

/// Convert a big int string to a big endian bytearray.
pub fn big_int_str_to_hash(value: &str) -> Vec<u8> {
    BigInt::from_str(value)
        .expect("Invalid big int string")
        .to_bytes_be()
        .1
}

/// Calculate the integer value from the bytearray.
pub fn calculate_value_from_bytearray(arr: &[u8]) -> usize {
    let sized: [u8; 8] = arr.try_into().expect("Invalid byte array");
    ((sized[7] as u16) | (sized[6] as u16) << 8).into()
}

/// Count the number of 0s in the bit array and check if the count satifies as the
/// smallest, non-negative solution to equation jwt_length + 1 + K = 448 (mod 512).
/// See more at 4.1(b) https://datatracker.ietf.org/doc/html/rfc4634#section-4.1
pub fn validate_zeros_count(arr: &[bool], jwt_length: usize) -> Result<(), SuiError> {
    // Count the number of 0s in the bitarray excluding the last 8 bytes (64 bits).
    let count = arr.iter().take(arr.len() - 64).filter(|&bit| !bit).count();
    if (jwt_length + 1 + count) % 512 == 448 && count < 512 {
        Ok(())
    } else {
        Err(SuiError::InvalidSignature {
            error: "Invalid bitarray".to_string(),
        })
    }
}

/// Given a chunk of bytearray, parse it as an ascii string and decode as a JWTHeader.
/// Return the JWTHeader if its fields are valid.
pub fn parse_and_validate_header(chunk: &[u8]) -> Result<JWTHeader, SuiError> {
    let header_str = std::str::from_utf8(chunk).map_err(|_| SuiError::InvalidSignature {
        error: "Cannot parse header string".to_string(),
    })?;
    let decoded_header =
        Base64UrlUnpadded::decode_vec(header_str).map_err(|_| SuiError::InvalidSignature {
            error: "Invalid jwt header".to_string(),
        })?;
    let json_header: Value =
        serde_json::from_slice(&decoded_header).map_err(|_| SuiError::InvalidSignature {
            error: "Invalid json".to_string(),
        })?;
    let header: JWTHeader =
        serde_json::from_value(json_header).map_err(|_| SuiError::InvalidSignature {
            error: "Cannot parse jwt header".to_string(),
        })?;
    if header.alg != "RS256" || header.typ != "JWT" {
        Err(SuiError::InvalidSignature {
            error: "Invalid header".to_string(),
        })
    } else {
        Ok(header)
    }
}

/// Calculate the poseidon hash from 10 selected fields in the aux inputs.
pub fn calculate_all_inputs_hash_from_aux_inputs(aux_inputs: &AuxInputs) -> String {
    // Safe to unwrap here all fields are converted to string from valid BigInt.
    let mut poseidon = PoseidonWrapper::new(10);
    let jwt_sha2_hash_0 = Bn254Fr::from_str(&aux_inputs.jwt_sha2_hash[0]).unwrap();
    let jwt_sha2_hash_1 = Bn254Fr::from_str(&aux_inputs.jwt_sha2_hash[1]).unwrap();
    let masked_content_hash = Bn254Fr::from_str(&aux_inputs.masked_content.hash).unwrap();
    let payload_start_index =
        Bn254Fr::from_str(&aux_inputs.payload_start_index.to_string()).unwrap();
    let payload_len = Bn254Fr::from_str(&aux_inputs.payload_len.to_string()).unwrap();
    let eph_public_key_0 = Bn254Fr::from_str(&aux_inputs.eph_public_key[0]).unwrap();
    let eph_public_key_1 = Bn254Fr::from_str(&aux_inputs.eph_public_key[1]).unwrap();
    let max_epoch = Bn254Fr::from_str(&aux_inputs.max_epoch.to_string()).unwrap();
    let nonce = Bn254Fr::from_str(&aux_inputs.masked_content.nonce).unwrap();
    let num_sha2_blocks = Bn254Fr::from_str(&aux_inputs.num_sha2_blocks.to_string()).unwrap();

    poseidon
        .hash(&[
            jwt_sha2_hash_0,
            jwt_sha2_hash_1,
            masked_content_hash,
            payload_start_index,
            payload_len,
            eph_public_key_0,
            eph_public_key_1,
            max_epoch,
            nonce,
            num_sha2_blocks,
        ])
        .to_string()
}
