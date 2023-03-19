// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::natives::NativesCostTable;
use fastcrypto::hash::{Blake2b256, HashFunction, Keccak256};
use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_core_types::vm_status::sub_status::NFE_OUT_OF_GAS;
use move_vm_runtime::{native_charge_gas_early_exit, native_functions::NativeContext};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};

fn hash<H: HashFunction<DIGEST_SIZE>, const DIGEST_SIZE: usize>(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
    gas_left: &mut InternalGas,
    cost_per_byte: InternalGas,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 1);

    let msg = pop_arg!(args, VectorRef);
    let msg_ref = msg.as_bytes_ref();

    match gas_left.checked_sub(cost_per_byte.mul((msg_ref.len() as u64).into())) {
        Some(x) => *gas_left = x,
        None => {
            // Exhausted all in budget. terminate early
            return Ok(NativeResult::err(context.gas_budget(), NFE_OUT_OF_GAS));
        }
    }

    Ok(NativeResult::ok(
        context.gas_budget().saturating_sub(*gas_left),
        smallvec![Value::vector_u8(H::digest(msg_ref.as_slice()).digest)],
    ))
}
#[derive(Clone)]
pub struct HashKeccak256CostParams {
    pub cost_base: InternalGas,

    pub data_cost_per_byte: InternalGas,
}
pub fn keccak256(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let mut gas_left = context.gas_budget();
    let hash_keccak256_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .hash_keccak256_cost_params
        .clone();
    native_charge_gas_early_exit!(context, gas_left, hash_keccak256_cost_params.cost_base);

    hash::<Keccak256, 32>(
        context,
        ty_args,
        args,
        &mut gas_left,
        hash_keccak256_cost_params.data_cost_per_byte,
    )
}

#[derive(Clone)]
pub struct HashBlake2b256CostParams {
    pub cost_base: InternalGas,

    pub data_cost_per_byte: InternalGas,
}
pub fn blake2b256(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let mut gas_left = context.gas_budget();
    let hash_blake2b256_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .hash_blake2b256_cost_params
        .clone();
    native_charge_gas_early_exit!(context, gas_left, hash_blake2b256_cost_params.cost_base);

    hash::<Blake2b256, 32>(
        context,
        ty_args,
        args,
        &mut gas_left,
        hash_blake2b256_cost_params.data_cost_per_byte,
    )
}
