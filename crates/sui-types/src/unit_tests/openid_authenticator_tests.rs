// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::AuxInputs;
use crate::{
    base_types::SuiAddress,
    crypto::{get_key_pair_from_rng, DefaultHash, Signature, SignatureScheme, SuiKeyPair},
    openid_authenticator::{
        OAuthProviderContent, OpenIdAuthenticator, ProofPoints, PublicInputs,
        SerializedVerifyingKey,
    },
    signature::{AuthenticatorTrait, GenericSignature},
    utils::make_transaction,
};
use fastcrypto::{hash::HashFunction, traits::EncodeDecodeBase64};
use rand::{rngs::StdRng, SeedableRng};
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};

pub fn keys() -> Vec<SuiKeyPair> {
    let mut seed = StdRng::from_seed([0; 32]);
    let kp1: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut seed).1);
    let kp2: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair_from_rng(&mut seed).1);
    let kp3: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair_from_rng(&mut seed).1);
    vec![kp1, kp2, kp3]
}

#[test]
fn openid_authenticator_scenarios() {
    let keys = keys();
    let foundation_key = &keys[0];
    let user_key = &keys[0];

    let vk = SerializedVerifyingKey::from_fp("./src/unit_tests/google.vkey");
    let public_inputs = PublicInputs::from_fp("./src/unit_tests/public.json");
    let proof_points = ProofPoints::from_fp("./src/unit_tests/google.proof");
    let aux_inputs = AuxInputs::from_fp("./src/unit_tests/aux.json").unwrap();

    let mut hasher = DefaultHash::default();
    hasher.update([SignatureScheme::OpenIdAuthenticator.flag()]);
    hasher.update(&vk.vk_gamma_abc_g1);
    hasher.update(&vk.alpha_g1_beta_g2);
    hasher.update(&vk.gamma_g2_neg_pc);
    hasher.update(&vk.delta_g2_neg_pc);
    let user_address = SuiAddress::from_bytes(hasher.finalize().digest).unwrap();

    // Create an example bulletin with 2 keys from Google.
    let example_bulletin = vec![
        OAuthProviderContent::new(
            "https://accounts.google.com".to_string(),
            "RSA".to_string(),
            "86969aec37a7780f18807877593bbbf8cf5de5ce".to_string(),
            "AQAB".to_string(),
            "zHv3roUMqfv4UbexMfPOA1hmPwAzfXr7Q7jz5hwgamvf8lD0zguxQZ80yCq9rwzIB8oP9w6AHPLbeexm0qhnXDHlO3Xnwt8T8URdrwSoLO9dKBwnXQiv1U6KPKXJUIfwZ0Vt3BPyhSMAZSUqqCA8OMVgxo0O4cgmmA5wAF57EqEOpUo73yEkmUMAUm-pSYoMfv_EfbMRC-sA2dpji6hCEouay45RK2EAXfyCTltVt2WFzZvKvtHaFVaorA3vQTqKBTHQ4-_qXAdiX0Oew3aLWv_Mlk0PCkfZKrGOIaPwyzWPizM52Lw5x_b-oCjJGrSMikD2-x4sHhXBHHIRlTP4JQ".to_string(),
            "RS256".to_string(),
            "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com".to_string()
        )
    ];

    // Sign the bulletin content with the sui foundation key as a personal message.
    let bulletin_sig = Signature::new_secure(
        &IntentMessage::new(
            Intent::sui_app(IntentScope::PersonalMessage),
            example_bulletin.clone(),
        ),
        foundation_key,
    );

    println!("bulletin sig: {:?}", bulletin_sig.encode_base64());

    // Sign the user transaction with the user's ephemeral key.
    let tx = make_transaction(user_address, user_key, Intent::sui_transaction());
    let s = match tx.inner().tx_signatures.first().unwrap() {
        GenericSignature::Signature(s) => s,
        _ => panic!("Expected a signature"),
    };

    let authenticator = OpenIdAuthenticator::new(
        vk,
        proof_points,
        public_inputs,
        aux_inputs,
        s.clone(),
        bulletin_sig,
        example_bulletin,
    );

    assert!(authenticator
        .verify_secure_generic(
            &IntentMessage::new(
                Intent::sui_transaction(),
                tx.into_data().transaction_data().clone()
            ),
            user_address,
            Some(0)
        )
        .is_ok());
}

#[test]
fn test_parsing() {
    let res = AuxInputs::from_fp("./src/unit_tests/aux.json");
    assert!(res.is_ok());
    let aux_inputs = res.unwrap();
    assert_eq!(aux_inputs.payload_start_index, 103);
    assert_eq!(aux_inputs.payload_len, 534);
    assert_eq!(
        aux_inputs.get_jwt_hash(),
        vec![
            118, 147, 129, 225, 127, 187, 123, 10, 143, 152, 201, 65, 7, 169, 168, 153, 181, 243,
            242, 165, 191, 167, 30, 214, 134, 27, 246, 235, 245, 93, 53, 245
        ]
    );
    assert_eq!(
        aux_inputs.get_eph_pub_key(),
        vec![
            13, 125, 171, 53, 140, 141, 173, 170, 78, 250, 0, 73, 167, 91, 7, 67, 101, 85, 177, 10,
            54, 130, 25, 187, 104, 15, 112, 87, 19, 73, 215, 117
        ]
    );

    let masked_content = aux_inputs.masked_content;
    assert_eq!(masked_content.iss, "https://accounts.google.com");
    assert_eq!(
        masked_content.wallet_id,
        "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com"
    );
    assert_eq!(
        masked_content.nonce,
        "16637918813908060261870528903994038721669799613803601616678155512181273289477"
    );
    assert_eq!(
        masked_content.hash,
        "15574265890121888853134966170838207038528069623841940909502184441509395967684"
    );

    let header = masked_content.header;
    assert_eq!(header.alg, "RS256".to_string());
    assert_eq!(header.typ, "JWT".to_string());
    assert_eq!(
        header.kid,
        "96971808796829a972e79a9d1a9fff11cd61b1e3".to_string()
    );
}

#[test]
fn test_poseidon() {

}