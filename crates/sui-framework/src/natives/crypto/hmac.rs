// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{natives::NativesCostTable};
use fastcrypto::{hmac, traits::ToFromBytes};
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

pub struct HmacHmacSha3256CostParams {
    pub cost_base: InternalGas,

    pub msg_cost_per_byte: InternalGas,
    pub pub_key_cost_per_byte: InternalGas,
}
pub fn hmac_sha3_256(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 2);

    let mut gas_left = context.gas_budget();
    let hmac_hmac_sha3256_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .hmac_hmac_sha3256_cost_params;
    native_charge_gas_early_exit!(context, gas_left, hmac_hmac_sha3256_cost_params.cost_base);

    let message = pop_arg!(args, VectorRef);
    let key = pop_arg!(args, VectorRef);

    let message_ref = message.as_bytes_ref();
    let key_ref = key.as_bytes_ref();

    let hmac_key = hmac::HmacKey::from_bytes(&key_ref).unwrap();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        hmac_hmac_sha3256_cost_params
            .msg_cost_per_byte
            .mul((message_ref.len() as u64).into())
            + hmac_hmac_sha3256_cost_params
                .pub_key_cost_per_byte
                .mul((key_ref.len() as u64).into())
    );

    let cost = native_gas_total_cost!(context, gas_left);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(
            hmac::hmac_sha3_256(&hmac_key, &message_ref).to_vec()
        )],
    ))
}
