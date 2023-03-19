// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::natives::NativesCostTable;
use fastcrypto::{
    bls12381::{min_pk, min_sig},
    traits::{ToFromBytes, VerifyingKey},
};
use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};

pub struct Bls12381MinSigVerifyCostParams {
    pub bls12381_bls12381_min_sig_verify_cost_base: InternalGas,
    pub msg_cost_per_byte: InternalGas,
    pub pub_key_cost_per_byte: InternalGas,
    pub signature_cost_per_byte: InternalGas,
}
pub fn bls12381_min_sig_verify(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 3);

    let mut gas_left = context.gas_budget();
    let bls12381_min_sig_verify_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .bls12381_min_sig_verify_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        bls12381_min_sig_verify_cost_params.bls12381_bls12381_min_sig_verify_cost_base
    );

    let msg = pop_arg!(args, VectorRef);
    let public_key_bytes = pop_arg!(args, VectorRef);
    let signature_bytes = pop_arg!(args, VectorRef);

    let msg_ref = msg.as_bytes_ref();
    let public_key_bytes_ref = public_key_bytes.as_bytes_ref();
    let signature_bytes_ref = signature_bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        bls12381_min_sig_verify_cost_params
            .msg_cost_per_byte
            .mul((msg_ref.len() as u64).into())
            + bls12381_min_sig_verify_cost_params
                .pub_key_cost_per_byte
                .mul((public_key_bytes_ref.len() as u64).into())
            + bls12381_min_sig_verify_cost_params
                .signature_cost_per_byte
                .mul((signature_bytes_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    let signature =
        match <min_sig::BLS12381Signature as ToFromBytes>::from_bytes(&signature_bytes_ref) {
            Ok(signature) => signature,
            Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
        };

    let public_key =
        match <min_sig::BLS12381PublicKey as ToFromBytes>::from_bytes(&public_key_bytes_ref) {
            Ok(public_key) => match public_key.validate() {
                Ok(_) => public_key,
                Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
            },
            Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
        };

    match public_key.verify(&msg_ref, &signature) {
        Ok(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(true)])),
        Err(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    }
}

pub struct Bls12381MinPkVerifyCostParams {
    pub bls12381_bls12381_min_pk_verify_cost_base: InternalGas,
    pub msg_cost_per_byte: InternalGas,
    pub pub_key_cost_per_byte: InternalGas,
    pub signature_cost_per_byte: InternalGas,
}
pub fn bls12381_min_pk_verify(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 3);

    let mut gas_left = context.gas_budget();
    let bls12381_min_pk_verify_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .bls12381_min_pk_verify_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        bls12381_min_pk_verify_cost_params.bls12381_bls12381_min_pk_verify_cost_base
    );

    let msg = pop_arg!(args, VectorRef);
    let public_key_bytes = pop_arg!(args, VectorRef);
    let signature_bytes = pop_arg!(args, VectorRef);

    let msg_ref = msg.as_bytes_ref();
    let public_key_bytes_ref = public_key_bytes.as_bytes_ref();
    let signature_bytes_ref = signature_bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        bls12381_min_pk_verify_cost_params
            .msg_cost_per_byte
            .mul((msg_ref.len() as u64).into())
            + bls12381_min_pk_verify_cost_params
                .pub_key_cost_per_byte
                .mul((public_key_bytes_ref.len() as u64).into())
            + bls12381_min_pk_verify_cost_params
                .signature_cost_per_byte
                .mul((signature_bytes_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    let signature =
        match <min_pk::BLS12381Signature as ToFromBytes>::from_bytes(&signature_bytes_ref) {
            Ok(signature) => signature,
            Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
        };

    let public_key =
        match <min_pk::BLS12381PublicKey as ToFromBytes>::from_bytes(&public_key_bytes_ref) {
            Ok(public_key) => match public_key.validate() {
                Ok(_) => public_key,
                Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
            },
            Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
        };

    match public_key.verify(&msg_ref, &signature) {
        Ok(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(true)])),
        Err(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    }
}
