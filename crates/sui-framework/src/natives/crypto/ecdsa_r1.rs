// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::natives::NativesCostTable;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Keccak256, Sha256};
use fastcrypto::traits::RecoverableSignature;
use fastcrypto::{
    secp256r1::{
        recoverable::Secp256r1RecoverableSignature, Secp256r1PublicKey, Secp256r1Signature,
    },
    traits::ToFromBytes,
};
use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_runtime::{native_charge_gas_early_exit, native_gas_total_cost};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};
use smallvec::smallvec;
use std::collections::VecDeque;
use std::ops::Mul;

pub const FAIL_TO_RECOVER_PUBKEY: u64 = 0;
pub const INVALID_SIGNATURE: u64 = 1;

pub const KECCAK256: u8 = 0;
pub const SHA256: u8 = 1;

pub struct EcdsaR1EcRecoverCostParams {
    pub ecdsa_r1_ecrecover_cost_base: InternalGas,

    pub hash_cost: InternalGas,
    pub msg_cost_per_byte: InternalGas,
    pub signature_cost_per_byte: InternalGas,
}
pub fn ecrecover(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 3);

    let mut gas_left = context.gas_budget();
    let ecdsa_r1_ecrecover_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .ecdsa_r1_ecrecover_cost_params;
    native_charge_gas_early_exit!(context, gas_left, ecdsa_r1_ecrecover_cost_params.ecdsa_r1_ecrecover_cost_base);

    let hash = pop_arg!(args, u8);
    let msg = pop_arg!(args, VectorRef);
    let signature = pop_arg!(args, VectorRef);

    let msg_ref = msg.as_bytes_ref();
    let signature_ref = signature.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        ecdsa_r1_ecrecover_cost_params.hash_cost
            + ecdsa_r1_ecrecover_cost_params
                .msg_cost_per_byte
                .mul((msg_ref.len() as u64).into())
            + ecdsa_r1_ecrecover_cost_params
                .signature_cost_per_byte
                .mul((signature_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    let sig = match <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&signature_ref) {
        Ok(s) => s,
        Err(_) => return Ok(NativeResult::err(cost, INVALID_SIGNATURE)),
    };

    let pk = match hash {
        KECCAK256 => sig.recover_with_hash::<Keccak256>(&msg_ref),
        SHA256 => sig.recover_with_hash::<Sha256>(&msg_ref),
        _ => Err(FastCryptoError::InvalidInput),
    };

    match pk {
        Ok(pk) => Ok(NativeResult::ok(
            cost,
            smallvec![Value::vector_u8(pk.as_bytes().to_vec())],
        )),
        Err(_) => Ok(NativeResult::err(cost, FAIL_TO_RECOVER_PUBKEY)),
    }
}

pub struct EcdsaR1Secp256R1VerifyCostParams {
    pub ecdsa_r1_secp256r1_verify_cost_base: InternalGas,

    pub hash_cost: InternalGas,
    pub msg_cost_per_byte: InternalGas,
    pub pub_key_cost_per_byte: InternalGas,
    pub signature_cost_per_byte: InternalGas,
}
pub fn secp256r1_verify(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 4);

    let mut gas_left = context.gas_budget();
    let ecdsa_r1_secp256r1_verify_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .ecdsa_r1_secp256r1_verify_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        ecdsa_r1_secp256r1_verify_cost_params.ecdsa_r1_secp256r1_verify_cost_base
    );

    let hash = pop_arg!(args, u8);
    let msg = pop_arg!(args, VectorRef);
    let public_key_bytes = pop_arg!(args, VectorRef);
    let signature_bytes = pop_arg!(args, VectorRef);

    let msg_ref = msg.as_bytes_ref();
    let public_key_bytes_ref = public_key_bytes.as_bytes_ref();
    let signature_bytes_ref = signature_bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        ecdsa_r1_secp256r1_verify_cost_params.hash_cost
            + ecdsa_r1_secp256r1_verify_cost_params
                .msg_cost_per_byte
                .mul((msg_ref.len() as u64).into())
            + ecdsa_r1_secp256r1_verify_cost_params
                .pub_key_cost_per_byte
                .mul((public_key_bytes_ref.len() as u64).into())
            + ecdsa_r1_secp256r1_verify_cost_params
                .signature_cost_per_byte
                .mul((signature_bytes_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    let sig = match <Secp256r1Signature as ToFromBytes>::from_bytes(&signature_bytes_ref) {
        Ok(s) => s,
        Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    };

    let pk = match <Secp256r1PublicKey as ToFromBytes>::from_bytes(&public_key_bytes_ref) {
        Ok(p) => p,
        Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    };

    let result = match hash {
        KECCAK256 => pk.verify_with_hash::<Keccak256>(&msg_ref, &sig).is_ok(),
        SHA256 => pk.verify_with_hash::<Sha256>(&msg_ref, &sig).is_ok(),
        _ => false,
    };

    Ok(NativeResult::ok(cost, smallvec![Value::bool(result)]))
}
