// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::natives::NativesCostTable;
use fastcrypto::vrf::ecvrf::ECVRFProof;
use fastcrypto::vrf::VRFProof;
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

pub const INVALID_ECVRF_HASH_LENGTH: u64 = 1;
pub const INVALID_ECVRF_PUBLIC_KEY: u64 = 2;
pub const INVALID_ECVRF_PROOF: u64 = 3;

pub struct EcvrfEcvrfVerifyCostParams {
    pub ecvrf_ecvrf_verify_cost_base: InternalGas,

    pub proof_cost_per_byte: InternalGas,
    pub public_key_cost_per_byte: InternalGas,
    pub alpha_string_cost_per_byte: InternalGas,
    pub hash_cost_per_byte: InternalGas,
}
pub fn ecvrf_verify(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 4);

    let mut gas_left = context.gas_budget();
    let ecvrf_ecvrf_verify_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .ecvrf_ecvrf_verify_cost_params;
    native_charge_gas_early_exit!(context, gas_left, ecvrf_ecvrf_verify_cost_params.ecvrf_ecvrf_verify_cost_base);

    let proof_bytes = pop_arg!(args, VectorRef);
    let public_key_bytes = pop_arg!(args, VectorRef);
    let alpha_string = pop_arg!(args, VectorRef);
    let hash_bytes = pop_arg!(args, VectorRef);

    let proof_bytes_ref = proof_bytes.as_bytes_ref();
    let public_key_bytes_ref = public_key_bytes.as_bytes_ref();
    let alpha_string_ref = alpha_string.as_bytes_ref();
    let hash_bytes_ref = hash_bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        ecvrf_ecvrf_verify_cost_params
            .proof_cost_per_byte
            .mul((proof_bytes_ref.len() as u64).into())
            + ecvrf_ecvrf_verify_cost_params
                .public_key_cost_per_byte
                .mul((public_key_bytes_ref.len() as u64).into())
            + ecvrf_ecvrf_verify_cost_params
                .alpha_string_cost_per_byte
                .mul((alpha_string_ref.len() as u64).into())
            + ecvrf_ecvrf_verify_cost_params
                .hash_cost_per_byte
                .mul((hash_bytes_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    let hash: [u8; 64] = match hash_bytes.as_bytes_ref().as_slice().try_into() {
        Ok(h) => h,
        Err(_) => return Ok(NativeResult::err(cost, INVALID_ECVRF_HASH_LENGTH)),
    };

    let public_key = match bcs::from_bytes(public_key_bytes.as_bytes_ref().as_slice()) {
        Ok(pk) => pk,
        Err(_) => return Ok(NativeResult::err(cost, INVALID_ECVRF_PUBLIC_KEY)),
    };

    let proof: ECVRFProof = match bcs::from_bytes(proof_bytes.as_bytes_ref().as_slice()) {
        Ok(p) => p,
        Err(_) => return Ok(NativeResult::err(cost, INVALID_ECVRF_PROOF)),
    };

    let result = proof.verify_output(alpha_string.as_bytes_ref().as_slice(), &public_key, &hash);
    Ok(NativeResult::ok(
        cost,
        smallvec![Value::bool(result.is_ok())],
    ))
}
