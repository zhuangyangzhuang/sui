// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::natives::NativesCostTable;
use fastcrypto_zkp::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{self, Value, VectorRef},
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};

pub const INVALID_VERIFYING_KEY: u64 = 0;

pub struct Groth16PrepareVerifyingKeyCostParams {
    pub groth16_prepare_verifying_key_cost_base: InternalGas,

    pub verifying_key_cost_per_byte: InternalGas,
}
pub fn prepare_verifying_key(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 1);

    let mut gas_left = context.gas_budget();
    let groth16_prepare_verifying_key_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .groth16_prepare_verifying_key_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        groth16_prepare_verifying_key_cost_params.groth16_prepare_verifying_key_cost_base
    );

    let bytes = pop_arg!(args, VectorRef);
    let verifying_key = bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        groth16_prepare_verifying_key_cost_params
            .verifying_key_cost_per_byte
            .mul((verifying_key.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    match prepare_pvk_bytes(&verifying_key) {
        Ok(pvk) => Ok(NativeResult::ok(
            cost,
            smallvec![Value::struct_(values::Struct::pack(vec![
                Value::vector_u8(pvk[0].to_vec()),
                Value::vector_u8(pvk[1].to_vec()),
                Value::vector_u8(pvk[2].to_vec()),
                Value::vector_u8(pvk[3].to_vec())
            ]))],
        )),
        Err(_) => Ok(NativeResult::err(cost, INVALID_VERIFYING_KEY)),
    }
}

pub struct Groth16VerifyGroth16ProofInternalCostParams {
    pub groth16_verify_groth16_proof_internal_cost_base: InternalGas,

    pub proof_points_cost_per_byte: InternalGas,
    pub public_proof_inputs_cost_per_byte: InternalGas,
    pub delta_g2_neg_pc_cost_per_byte: InternalGas,
    pub gamma_g2_neg_pc_cost_per_byte: InternalGas,
    pub alpha_g1_beta_g2_cost_per_byte: InternalGas,
    pub vk_gamma_abc_g1_cost_per_byte: InternalGas,
}
pub fn verify_groth16_proof_internal(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 6);

    let mut gas_left = context.gas_budget();
    let groth16_verify_groth16_proof_internal_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .groth16_pverify_groth16_proof_internal_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        groth16_verify_groth16_proof_internal_cost_params.groth16_verify_groth16_proof_internal_cost_base
    );

    let bytes5 = pop_arg!(args, VectorRef);
    let proof_points = bytes5.as_bytes_ref();

    let bytes4 = pop_arg!(args, VectorRef);
    let public_proof_inputs = bytes4.as_bytes_ref();

    let bytes3 = pop_arg!(args, VectorRef);
    let delta_g2_neg_pc = bytes3.as_bytes_ref();

    let bytes2 = pop_arg!(args, VectorRef);
    let gamma_g2_neg_pc = bytes2.as_bytes_ref();

    let byte1 = pop_arg!(args, VectorRef);
    let alpha_g1_beta_g2 = byte1.as_bytes_ref();

    let bytes = pop_arg!(args, VectorRef);
    let vk_gamma_abc_g1 = bytes.as_bytes_ref();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        groth16_verify_groth16_proof_internal_cost_params
            .proof_points_cost_per_byte
            .mul((proof_points.len() as u64).into())
            + groth16_verify_groth16_proof_internal_cost_params
                .public_proof_inputs_cost_per_byte
                .mul((public_proof_inputs.len() as u64).into())
            + groth16_verify_groth16_proof_internal_cost_params
                .delta_g2_neg_pc_cost_per_byte
                .mul((delta_g2_neg_pc.len() as u64).into())
            + groth16_verify_groth16_proof_internal_cost_params
                .gamma_g2_neg_pc_cost_per_byte
                .mul((gamma_g2_neg_pc.len() as u64).into())
            + groth16_verify_groth16_proof_internal_cost_params
                .alpha_g1_beta_g2_cost_per_byte
                .mul((alpha_g1_beta_g2.len() as u64).into())
            + groth16_verify_groth16_proof_internal_cost_params
                .vk_gamma_abc_g1_cost_per_byte
                .mul((vk_gamma_abc_g1.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    match verify_groth16_in_bytes(
        &vk_gamma_abc_g1,
        &alpha_g1_beta_g2,
        &gamma_g2_neg_pc,
        &delta_g2_neg_pc,
        &public_proof_inputs,
        &proof_points,
    ) {
        Ok(res) => {
            if res {
                Ok(NativeResult::ok(cost, smallvec![Value::bool(true)]))
            } else {
                Ok(NativeResult::ok(cost, smallvec![Value::bool(false)]))
            }
        }
        Err(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    }
}
