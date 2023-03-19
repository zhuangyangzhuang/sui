// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::natives::NativesCostTable;
use fastcrypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    traits::{ToFromBytes, VerifyingKey},
};
use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::{native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};

pub struct Ed25519VerifyCostParams {
    pub ed25519_ed25519_verify_cost_base: InternalGas,

    pub msg_cost_per_byte: InternalGas,

    
    pub pub_key_cost_per_byte: InternalGas,
    pub signature_cost_per_byte: InternalGas,
}
pub fn ed25519_verify(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 3);

    let mut gas_left = context.gas_budget();
    let ed25519_verify_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .ed25519_verify_cost_params;
    native_charge_gas_early_exit!(context, gas_left, ed25519_verify_cost_params.ed25519_ed25519_verify_cost_base);

    let msg = pop_arg!(args, VectorRef);
    let msg_ref = msg.as_bytes_ref();
    let public_key_bytes = pop_arg!(args, VectorRef);
    let public_key_bytes_ref = public_key_bytes.as_bytes_ref();
    let signature_bytes = pop_arg!(args, VectorRef);
    let signature_bytes_ref = signature_bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        ed25519_verify_cost_params
            .msg_cost_per_byte
            .mul((msg_ref.len() as u64).into())
            + ed25519_verify_cost_params
                .pub_key_cost_per_byte
                .mul((public_key_bytes_ref.len() as u64).into())
            + ed25519_verify_cost_params
                .signature_cost_per_byte
                .mul((signature_bytes_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    let signature = match <Ed25519Signature as ToFromBytes>::from_bytes(&signature_bytes_ref) {
        Ok(signature) => signature,
        Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    };

    let public_key = match <Ed25519PublicKey as ToFromBytes>::from_bytes(&public_key_bytes_ref) {
        Ok(public_key) => public_key,
        Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    };

    match public_key.verify(&msg_ref, &signature) {
        Ok(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(true)])),
        Err(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    }
}
