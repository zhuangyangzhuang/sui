// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    legacy_emit_cost,
    natives::{object_runtime::ObjectRuntime, NativesCostTable},
};
use move_binary_format::errors::PartialVMResult;
use move_core_types::{account_address::AccountAddress, gas_algebra::InternalGas};
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{StructRef, Value},
};
use smallvec::smallvec;
use std::collections::VecDeque;

pub struct BorrowUidCostParams {
    pub obj_borrow_field_cost: InternalGas,
}
/***************************************************************************************************
 * native fun borrow_uid
 * Implementation of the Move native function `borrow_uid<T: key>(obj: &T): &UID`
 *   gas cost: obj_borrow_field_cost                | this is hard to calculate. Making it flat
 **************************************************************************************************/
pub fn borrow_uid(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let natvies_cost_table: &NativesCostTable = context.extensions_mut().get();
    let borrow_uid_cost_params = &natvies_cost_table.borrow_uid_cost_params;

    native_charge_gas_early_exit!(
        context,
        gas_left,
        borrow_uid_cost_params.obj_borrow_field_cost
    );

    let obj = pop_arg!(args, StructRef);
    let id_field = obj.borrow_field(0)?;

    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![id_field],
    ))
}

pub struct DeleteImplCostParams {
    pub delete_id_cost: InternalGas,
}
/***************************************************************************************************
 * native fun delete_impl
 * Implementation of the Move native function `delete_impl(id: address)`
 *   gas cost: delete_id_cost                | this is a simple ID deletion
 **************************************************************************************************/
pub fn delete_impl(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let natvies_cost_table: &NativesCostTable = context.extensions_mut().get();
    let delete_impl_cost_params = &natvies_cost_table.delete_impl_cost_params;
    native_charge_gas_early_exit!(context, gas_left, delete_impl_cost_params.delete_id_cost);

    // unwrap safe because the interface of native function guarantees it.
    let uid_bytes = pop_arg!(args, AccountAddress);

    let obj_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();
    obj_runtime.delete_id(uid_bytes.into())?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![],
    ))
}

pub struct RecordNewIdCostParams {
    pub record_new_id_cost: InternalGas,
}
/***************************************************************************************************
 * native fun record_new_uid
 * Implementation of the Move native function `record_new_uid(id: address)`
 *   gas cost: record_new_id_cost                | this is a simple ID addition
 **************************************************************************************************/
// native fun record_new_uid(id: address);
pub fn record_new_uid(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let natvies_cost_table: &NativesCostTable = context.extensions_mut().get();
    let record_new_id_cost_params = &natvies_cost_table.record_new_id_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        record_new_id_cost_params.record_new_id_cost
    );

    // unwrap safe because the interface of native function guarantees it.
    let uid_bytes = pop_arg!(args, AccountAddress);

    let obj_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();
    obj_runtime.new_id(uid_bytes.into())?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![],
    ))
}
