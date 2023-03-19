// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use move_binary_format::errors::PartialVMResult;
use move_core_types::{account_address::AccountAddress, gas_algebra::InternalGas};
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::Value,
};
use smallvec::smallvec;
use std::{collections::VecDeque, convert::TryFrom, ops::Mul};
use sui_types::base_types::{ObjectID, TransactionDigest};

use crate::natives::{object_runtime::ObjectRuntime, NativesCostTable};

#[derive(Clone)]
pub struct TxContextDeriveIdCostParams {
    pub tx_context_derive_id_cost_base: InternalGas,
    pub calculate_tx_digest_cost_per_byte: InternalGas,
    pub derive_address_cost_per_byte: InternalGas,
    pub record_new_id_cost: InternalGas,
    pub create_move_value_cost_per_byte: InternalGas,
}
/***************************************************************************************************
 * native fun derive_id
 * Implementation of the Move native function `fun derive_id(tx_hash: vector<u8>, ids_created: u64): address`
 *   gas cost: obj_borrow_field_cost                | this is hard to calculate. Making it flat
 **************************************************************************************************/
pub fn derive_id(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 2);
    let mut gas_left = context.gas_budget();
    let tx_context_derive_id_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .tx_context_derive_id_cost_params.clone();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        tx_context_derive_id_cost_params.tx_context_derive_id_cost_base
    );

    let ids_created = pop_arg!(args, u64);
    let tx_hash = pop_arg!(args, Vec<u8>);

    native_charge_gas_early_exit!(
        context,
        gas_left,
        tx_context_derive_id_cost_params
            .calculate_tx_digest_cost_per_byte
            .mul((tx_hash.len() as u64).into())
    );

    // TODO(https://github.com/MystenLabs/sui/issues/58): finalize digest format
    // unwrap safe because all digests in Move are serialized from the Rust `TransactionDigest`
    let digest = TransactionDigest::try_from(tx_hash.as_slice()).unwrap();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        tx_context_derive_id_cost_params
            .derive_address_cost_per_byte
            .mul((TransactionDigest::LENGTH as u64).into())
    );

    let address = AccountAddress::from(ObjectID::derive_id(digest, ids_created));
    let obj_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        tx_context_derive_id_cost_params
            .create_move_value_cost_per_byte
            .mul((AccountAddress::LENGTH as u64).into())
    );

    obj_runtime.new_id(address.into())?;

    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![Value::address(address)],
    ))
}
