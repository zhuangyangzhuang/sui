// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::object_runtime::{ObjectRuntime, TransferResult};
use crate::natives::NativesCostTable;
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_core_types::{
    account_address::AccountAddress, gas_algebra::InternalGas, language_storage::TypeTag,
    vm_status::StatusCode,
};
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::Value,
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};
use sui_types::{
    base_types::{MoveObjectType, SequenceNumber},
    object::Owner,
};

const E_SHARED_NON_NEW_OBJECT: u64 = 0;

pub struct TransferInternalCostParams {
    pub transfer_transfer_internal_cost_base: InternalGas,
    pub derive_owner_cost_per_byte: InternalGas,
}
/***************************************************************************************************
* native fun transfer_internal
* Implementation of the Move native function `transfer_internal<T: key>(obj: T, recipient: vector<u8>, to_object: bool)`
*

**************************************************************************************************/
/// Implementation of Move native function
/// `transfer_internal<T: key>(obj: T, recipient: vector<u8>, to_object: bool)`
pub fn transfer_internal(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 2);
    let mut gas_left = context.gas_budget();
    let transfer_internal_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .transfer_internal_cost_params;
    native_charge_gas_early_exit!(context, gas_left, transfer_internal_cost_params.transfer_transfer_internal_cost_base);

    let ty = ty_args.pop().unwrap();
    let recipient = pop_arg!(args, AccountAddress);
    let obj = args.pop_back().unwrap();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        transfer_internal_cost_params
            .derive_owner_cost_per_byte
            .mul((AccountAddress::LENGTH as u64).into())
    );

    let owner = Owner::AddressOwner(recipient.into());

    let object_runtime_transfer_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .object_runtime_transfer_cost_params;
    let type_size = u64::from(ty.size());
    let obj_size = u64::from(obj.legacy_size());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        object_runtime_transfer_cost_params.transfer_object_runtime_transfer_cost_base
            + object_runtime_transfer_cost_params
                .transfer_impl_type_cost_per_byte
                .mul(type_size.into())
            + object_runtime_transfer_cost_params
                .transfer_impl_obj_cost_per_byte
                .mul(obj_size.into())
            + object_runtime_transfer_cost_params
                .transfer_impl_owner_cost_per_byte
                .mul(Owner::object_size_for_gas_metering().into())
    );

    object_runtime_transfer(context, owner, ty, obj)?;

    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![],
    ))
}

pub struct FreezeObjectCostParams {
    pub transfer_freeze_object_cost_base: InternalGas,
}
/// Implementation of Move native function
/// `freeze_object<T: key>(obj: T)`
pub fn freeze_object(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let freeze_object_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .freeze_object_cost_params;
    native_charge_gas_early_exit!(context, gas_left, freeze_object_cost_params.transfer_freeze_object_cost_base);

    let ty = ty_args.pop().unwrap();
    let obj = args.pop_back().unwrap();

    let object_runtime_transfer_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .object_runtime_transfer_cost_params;
    let type_size = u64::from(ty.size());
    let obj_size = u64::from(obj.legacy_size());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        object_runtime_transfer_cost_params.transfer_object_runtime_transfer_cost_base
            + object_runtime_transfer_cost_params
                .transfer_impl_type_cost_per_byte
                .mul(type_size.into())
            + object_runtime_transfer_cost_params
                .transfer_impl_obj_cost_per_byte
                .mul(obj_size.into())
            + object_runtime_transfer_cost_params
                .transfer_impl_owner_cost_per_byte
                .mul(Owner::object_size_for_gas_metering().into())
    );

    object_runtime_transfer(context, Owner::Immutable, ty, obj)?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![],
    ))
}

pub struct ShareObjectCostParams {
    pub transfer_share_object_cost_base: InternalGas,
}
/// Implementation of Move native function
/// `share_object<T: key>(obj: T)`
pub fn share_object(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let share_object_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .share_object_cost_params;
    native_charge_gas_early_exit!(context, gas_left, share_object_cost_params.transfer_share_object_cost_base);

    let ty = ty_args.pop().unwrap();
    let obj = args.pop_back().unwrap();

    let object_runtime_transfer_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .object_runtime_transfer_cost_params;
    let type_size = u64::from(ty.size());
    let obj_size = u64::from(obj.legacy_size());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        object_runtime_transfer_cost_params.transfer_object_runtime_transfer_cost_base
            + object_runtime_transfer_cost_params
                .transfer_impl_type_cost_per_byte
                .mul(type_size.into())
            + object_runtime_transfer_cost_params
                .transfer_impl_obj_cost_per_byte
                .mul(obj_size.into())
            + object_runtime_transfer_cost_params
                .transfer_impl_owner_cost_per_byte
                .mul(Owner::object_size_for_gas_metering().into())
    );

    let transfer_result = object_runtime_transfer(
        context,
        // Dummy version, to be filled with the correct initial version when the effects of the
        // transaction are written to storage.
        Owner::Shared {
            initial_shared_version: SequenceNumber::new(),
        },
        ty,
        obj,
    )?;
    let cost = native_gas_total_cost!(context, gas_left);
    Ok(match transfer_result {
        // New means the ID was created in this transaction
        // SameOwner means the object was previously shared and was re-shared; since
        // shared objects cannot be taken by-value in the adapter, this can only
        // happen via test_scenario
        TransferResult::New | TransferResult::SameOwner => NativeResult::ok(cost, smallvec![]),
        TransferResult::OwnerChanged => NativeResult::err(cost, E_SHARED_NON_NEW_OBJECT),
    })
}

pub struct ObjectRuntimeTransferCostParams {
    pub transfer_object_runtime_transfer_cost_base: InternalGas,
    pub transfer_impl_type_cost_per_byte: InternalGas,
    pub transfer_impl_obj_cost_per_byte: InternalGas,
    pub transfer_impl_owner_cost_per_byte: InternalGas,
}
/***************************************************************************************************
 * helper function
 *   gas cost: cost_base                        | base cost for this oper
 *              +
 **************************************************************************************************/
/// We dont actually charge in this, but the caller should charge before calling
fn object_runtime_transfer(
    context: &mut NativeContext,
    owner: Owner,
    ty: Type,
    obj: Value,
) -> PartialVMResult<TransferResult> {
    let tag = match context.type_to_type_tag(&ty)? {
        TypeTag::Struct(s) => *s,
        _ => {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Sui verifier guarantees this is a struct".to_string()),
            )
        }
    };
    let obj_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();
    obj_runtime.transfer(owner, ty, MoveObjectType::from(tag), obj)
}
