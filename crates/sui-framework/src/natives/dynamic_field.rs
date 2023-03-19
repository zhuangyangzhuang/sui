// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::natives::{
    get_nested_struct_field, get_object_id,
    object_runtime::{object_store::ObjectResult, ObjectRuntime},
    NativesCostTable,
};
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_core_types::{
    account_address::AccountAddress,
    gas_algebra::InternalGas,
    language_storage::{StructTag, TypeTag},
    value::MoveTypeLayout,
    vm_status::StatusCode,
};
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
use std::{collections::VecDeque, ops::Mul};
use sui_types::{base_types::MoveObjectType, dynamic_field::derive_dynamic_field_id};

const E_KEY_DOES_NOT_EXIST: u64 = 1;
const E_FIELD_TYPE_MISMATCH: u64 = 2;
const E_BCS_SERIALIZATION_FAILURE: u64 = 3;

macro_rules! get_or_fetch_object {
    ($context:ident, $gas_left:ident, $ty_args:ident, $parent:ident, $child_id:ident) => {{
        let child_ty = $ty_args.pop().unwrap();
        assert!($ty_args.is_empty());
        let (layout, tag) = match get_tag_and_layout($context, &child_ty)? {
            Some(res) => res,
            None => {
                return Ok(NativeResult::err(
                    native_gas_total_cost!($context, $gas_left),
                    E_BCS_SERIALIZATION_FAILURE,
                ))
            }
        };
        let object_runtime: &mut ObjectRuntime = $context.extensions_mut().get_mut();
        object_runtime.get_or_fetch_child_object(
            $parent,
            $child_id,
            &child_ty,
            layout,
            MoveObjectType::from(tag),
        )?
    }};
}

#[derive(Clone)]
pub struct HashTypeAndKeyCostParams {
    pub dynamic_field_hash_type_and_key_cost_base: InternalGas,
    pub type_to_type_tag_cost_per_byte: InternalGas,
    pub type_to_type_layout_cost_per_byte: InternalGas,
    pub parent_derive_dynamic_field_id_cost_per_byte: InternalGas,
    pub type_tag_derive_dynamic_field_id_cost_per_byte: InternalGas,
    pub type_layout_derive_dynamic_field_id_cost_per_byte: InternalGas,
    pub value_derive_dynamic_field_id_cost_per_byte: InternalGas,
}
// native fun hash_type_and_key<K: copy + drop + store>(parent: address, k: K): address;
pub fn hash_type_and_key(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 1);
    assert_eq!(args.len(), 2);

    let mut gas_left = context.gas_budget();
    let hash_type_and_key_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .hash_type_and_key_cost_params
        .clone();

    // Charge base cost
    native_charge_gas_early_exit!(
        context,
        gas_left,
        hash_type_and_key_cost_params.dynamic_field_hash_type_and_key_cost_base
    );

    let k_ty = ty_args.pop().unwrap();
    let k: Value = args.pop_back().unwrap();
    let parent = pop_arg!(args, AccountAddress);

    let k_ty_size = u64::from(k_ty.size());
    let k_value_size = u64::from(k.legacy_size());

    // Type Tag derivation
    native_charge_gas_early_exit!(
        context,
        gas_left,
        hash_type_and_key_cost_params
            .type_to_type_tag_cost_per_byte
            .mul(k_ty_size.into())
    );
    let k_tag = context.type_to_type_tag(&k_ty)?;

    // Type Layout derivation
    native_charge_gas_early_exit!(
        context,
        gas_left,
        hash_type_and_key_cost_params
            .type_to_type_layout_cost_per_byte
            .mul(k_ty_size.into())
    );
    let k_layout = match context.type_to_type_layout(&k_ty) {
        Ok(Some(layout)) => layout,
        _ => {
            return Ok(NativeResult::err(
                native_gas_total_cost!(context, gas_left),
                E_BCS_SERIALIZATION_FAILURE,
            ))
        }
    };

    let k_tag_size = u64::from(k_tag.abstract_size_for_gas_metering());

    // TODO: need a way to get layout size
    // assume roughly similar
    let k_layout_size = k_tag_size;

    // Dynamic field id derivation
    native_charge_gas_early_exit!(
        context,
        gas_left,
        hash_type_and_key_cost_params
            .parent_derive_dynamic_field_id_cost_per_byte
            .mul((AccountAddress::LENGTH as u64).into())
            + hash_type_and_key_cost_params
                .type_tag_derive_dynamic_field_id_cost_per_byte
                .mul(k_tag_size.into())
            + hash_type_and_key_cost_params
                .type_layout_derive_dynamic_field_id_cost_per_byte
                .mul(k_layout_size.into())
            + hash_type_and_key_cost_params
                .value_derive_dynamic_field_id_cost_per_byte
                .mul(k_value_size.into())
    );
    let cost = native_gas_total_cost!(context, gas_left);

    let Some(id) = derive_dynamic_field_id(parent, &k_tag, &k_layout, &k) else {
        return Ok(NativeResult::err(
            cost,
            E_BCS_SERIALIZATION_FAILURE,
        ));
    };

    Ok(NativeResult::ok(cost, smallvec![Value::address(id.into())]))
}

#[derive(Clone)]
pub struct AddChildObjectCostParams {
    pub dynamic_field_add_child_object_cost_base: InternalGas,

    pub child_id_extraction_cost_per_byte: InternalGas,
    pub child_type_to_type_tag_cost_per_byte: InternalGas,
    pub parent_object_runtime_cost_per_byte: InternalGas,
    pub child_id_object_runtime_cost_per_byte: InternalGas,
    pub child_type_object_runtime_cost_per_byte: InternalGas,
    pub child_struct_tag_object_runtime_cost_per_byte: InternalGas,
    pub child_value_tag_object_runtime_cost_per_byte: InternalGas,
}
// throws `E_KEY_ALREADY_EXISTS` if a child already exists with that ID
// native fun add_child_object<Child: key>(parent: address, child: Child);
pub fn add_child_object(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(ty_args.len() == 1);
    assert!(args.len() == 2);

    let mut gas_left = context.gas_budget();
    let add_child_object_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .add_child_object_cost_params
        .clone();
    native_charge_gas_early_exit!(
        context,
        gas_left,
        add_child_object_cost_params.dynamic_field_add_child_object_cost_base
    );

    let child = args.pop_back().unwrap();
    let parent = pop_arg!(args, AccountAddress).into();
    assert!(args.is_empty());

    let child_value_size = u64::from(child.legacy_size());

    // ID extraction step
    native_charge_gas_early_exit!(
        context,
        gas_left,
        add_child_object_cost_params
            .child_id_extraction_cost_per_byte
            .mul(child_value_size.into())
    );

    // TODO remove this copy_value, which will require VM changes
    let child_id = get_object_id(child.copy_value().unwrap())
        .unwrap()
        .value_as::<AccountAddress>()
        .unwrap()
        .into();

    // Type tag derivation step
    let child_ty = ty_args.pop().unwrap();
    let child_type_size = u64::from(child_ty.size());
    native_charge_gas_early_exit!(
        context,
        gas_left,
        add_child_object_cost_params
            .child_type_to_type_tag_cost_per_byte
            .mul(child_type_size.into())
    );

    assert!(ty_args.is_empty());
    let tag = match context.type_to_type_tag(&child_ty)? {
        TypeTag::Struct(s) => *s,
        _ => {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Sui verifier guarantees this is a struct".to_string()),
            )
        }
    };
    let struct_tag_size = u64::from(tag.abstract_size_for_gas_metering());

    // Object runtime `add_child_object` step
    native_charge_gas_early_exit!(
        context,
        gas_left,
        add_child_object_cost_params
            .parent_object_runtime_cost_per_byte
            .mul((AccountAddress::LENGTH as u64).into())
            + add_child_object_cost_params
                .child_id_object_runtime_cost_per_byte
                .mul((AccountAddress::LENGTH as u64).into())
            + add_child_object_cost_params
                .child_type_object_runtime_cost_per_byte
                .mul(child_type_size.into())
            + add_child_object_cost_params
                .child_struct_tag_object_runtime_cost_per_byte
                .mul(struct_tag_size.into())
            + add_child_object_cost_params
                .child_struct_tag_object_runtime_cost_per_byte
                .mul(struct_tag_size.into())
            + add_child_object_cost_params
                .child_value_tag_object_runtime_cost_per_byte
                .mul(child_value_size.into())
    );

    let object_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();
    object_runtime.add_child_object(
        parent,
        child_id,
        &child_ty,
        MoveObjectType::from(tag),
        child,
    )?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![],
    ))
}

#[derive(Clone)]
pub struct BorrowChildObjectCostParams {
    pub dynamic_field_borrow_child_object_cost_base: InternalGas,

    pub parent_uid_read_ref_cost_per_byte: InternalGas,
    pub parent_uid_get_nested_struct_field_cost_per_byte: InternalGas,

    pub parent_get_or_fetch_object_cost_per_byte: InternalGas,
    pub child_id_get_or_fetch_object_cost_per_byte: InternalGas,
    pub child_type_get_or_fetch_object_cost_per_byte: InternalGas,

    pub global_value_exists_cost: InternalGas,
    pub global_value_borrow_global_cost: InternalGas,
}
// throws `E_KEY_DOES_NOT_EXIST` if a child does not exist with that ID at that type
// or throws `E_FIELD_TYPE_MISMATCH` if the type does not match
// native fun borrow_child_object<Child: key>(parent: &UID, id: address): &Child;
// and (as the runtime does not distinguish different reference types)
// native fun borrow_child_object_mut<Child: key>(parent: &mut UID, id: address): &mut Child;
pub fn borrow_child_object(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(ty_args.len() == 1);
    assert!(args.len() == 2);

    let mut gas_left = context.gas_budget();
    let borrow_child_object_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .borrow_child_object_cost_params
        .clone();
    native_charge_gas_early_exit!(
        context,
        gas_left,
        borrow_child_object_cost_params.dynamic_field_borrow_child_object_cost_base
    );

    let child_id = pop_arg!(args, AccountAddress).into();

    let parent_uid = pop_arg!(args, StructRef).read_ref().unwrap();
    let parent_uid_size = u64::from(parent_uid.legacy_size());
    let child_id_size = AccountAddress::LENGTH as u64;
    // Okay to unwrap since we checked that size of Vec is 1
    let child_type_size = u64::from(ty_args.get(0).unwrap().size());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        borrow_child_object_cost_params
            .parent_uid_read_ref_cost_per_byte
            .mul(parent_uid_size.into())
            + borrow_child_object_cost_params
                .parent_uid_get_nested_struct_field_cost_per_byte
                .mul(parent_uid_size.into())
            + borrow_child_object_cost_params
                .parent_get_or_fetch_object_cost_per_byte
                .mul(parent_uid_size.into())
            + borrow_child_object_cost_params
                .child_id_get_or_fetch_object_cost_per_byte
                .mul(child_id_size.into())
            + borrow_child_object_cost_params
                .child_type_get_or_fetch_object_cost_per_byte
                .mul(child_type_size.into())
    );

    // UID { id: ID { bytes: address } }
    let parent = get_nested_struct_field(parent_uid, &[0, 0])
        .unwrap()
        .value_as::<AccountAddress>()
        .unwrap()
        .into();

    assert!(args.is_empty());
    let global_value_result = get_or_fetch_object!(context, gas_left, ty_args, parent, child_id);
    let global_value = match global_value_result {
        ObjectResult::MismatchedType => {
            return Ok(NativeResult::err(
                native_gas_total_cost!(context, gas_left),
                E_FIELD_TYPE_MISMATCH,
            ))
        }
        ObjectResult::Loaded(gv) => gv,
    };

    native_charge_gas_early_exit!(
        context,
        gas_left,
        borrow_child_object_cost_params.global_value_exists_cost
    );
    if !global_value.exists()? {
        return Ok(NativeResult::err(
            native_gas_total_cost!(context, gas_left),
            E_KEY_DOES_NOT_EXIST,
        ));
    }

    native_charge_gas_early_exit!(
        context,
        gas_left,
        borrow_child_object_cost_params.global_value_borrow_global_cost
    );
    let child_ref = global_value.borrow_global().map_err(|err| {
        assert!(err.major_status() != StatusCode::MISSING_DATA);
        err
    })?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![child_ref],
    ))
}

#[derive(Clone)]
pub struct RemoveChildObjectCostParams {
    pub dynamic_field_remove_child_object_cost_base: InternalGas,

    pub parent_get_or_fetch_object_cost_per_byte: InternalGas,
    pub child_id_get_or_fetch_object_cost_per_byte: InternalGas,
    pub child_type_get_or_fetch_object_cost_per_byte: InternalGas,

    pub global_value_exists_cost: InternalGas,
    pub global_value_move_from_cost: InternalGas,
}
// throws `E_KEY_DOES_NOT_EXIST` if a child does not exist with that ID at that type
// or throws `E_FIELD_TYPE_MISMATCH` if the type does not match
// native fun remove_child_object<Child: key>(parent: address, id: address): Child;
pub fn remove_child_object(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(ty_args.len() == 1);
    assert!(args.len() == 2);

    let mut gas_left = context.gas_budget();
    let remove_child_object_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .remove_child_object_cost_params
        .clone();
    native_charge_gas_early_exit!(
        context,
        gas_left,
        remove_child_object_cost_params.dynamic_field_remove_child_object_cost_base
    );

    let child_id = pop_arg!(args, AccountAddress).into();
    let parent = pop_arg!(args, AccountAddress).into();
    assert!(args.is_empty());

    let parent_uid_size = AccountAddress::LENGTH as u64;
    let child_id_size = AccountAddress::LENGTH as u64;
    // Okay to unwrap since we checked that size of Vec is 1
    let child_type_size = u64::from(ty_args.get(0).unwrap().size());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        remove_child_object_cost_params
            .parent_get_or_fetch_object_cost_per_byte
            .mul(parent_uid_size.into())
            + remove_child_object_cost_params
                .child_id_get_or_fetch_object_cost_per_byte
                .mul(child_id_size.into())
            + remove_child_object_cost_params
                .child_type_get_or_fetch_object_cost_per_byte
                .mul(child_type_size.into())
    );

    let global_value_result = get_or_fetch_object!(context, gas_left, ty_args, parent, child_id);
    let global_value = match global_value_result {
        ObjectResult::MismatchedType => {
            return Ok(NativeResult::err(
                native_gas_total_cost!(context, gas_left),
                E_FIELD_TYPE_MISMATCH,
            ))
        }
        ObjectResult::Loaded(gv) => gv,
    };

    native_charge_gas_early_exit!(
        context,
        gas_left,
        remove_child_object_cost_params.global_value_exists_cost
    );
    if !global_value.exists()? {
        return Ok(NativeResult::err(
            native_gas_total_cost!(context, gas_left),
            E_KEY_DOES_NOT_EXIST,
        ));
    }

    native_charge_gas_early_exit!(
        context,
        gas_left,
        remove_child_object_cost_params.global_value_move_from_cost
    );
    let child = global_value.move_from().map_err(|err| {
        assert!(err.major_status() != StatusCode::MISSING_DATA);
        err
    })?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![child],
    ))
}

pub struct HasChildObjectCostParams {
    // All inputs are constant same size. No need for special costing as this is a lookup
    pub dynamic_field_has_child_object_cost_base: InternalGas,
}
//native fun has_child_object(parent: address, id: address): bool;
pub fn has_child_object(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(ty_args.is_empty());
    assert!(args.len() == 2);

    let mut gas_left = context.gas_budget();
    let has_child_object_cost_params = &context
        .extensions_mut()
        .get::<NativesCostTable>()
        .has_child_object_cost_params;
    native_charge_gas_early_exit!(
        context,
        gas_left,
        has_child_object_cost_params.dynamic_field_has_child_object_cost_base
    );

    let child_id = pop_arg!(args, AccountAddress).into();
    let parent = pop_arg!(args, AccountAddress).into();
    let object_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();
    let has_child = object_runtime.child_object_exists(parent, child_id)?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![Value::bool(has_child)],
    ))
}

#[derive(Clone)]
pub struct HasChildObjectWithTyCostParams {
    pub dynamic_field_has_child_object_with_ty_cost_base: InternalGas,

    pub type_to_type_tag_cost_per_byte: InternalGas,
    pub parent_child_object_exists_and_has_type_cost_per_byte: InternalGas,
    pub child_id_child_object_exists_and_has_type_cost_per_byte: InternalGas,
    pub struct_tag_child_object_exists_and_has_type_cost_per_byte: InternalGas,
}
//native fun has_child_object_with_ty<Child: key>(parent: address, id: address): bool;
pub fn has_child_object_with_ty(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(ty_args.len() == 1);
    assert!(args.len() == 2);

    let mut gas_left = context.gas_budget();
    let has_child_object_with_ty_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .has_child_object_with_ty_cost_params
        .clone();
    native_charge_gas_early_exit!(
        context,
        gas_left,
        has_child_object_with_ty_cost_params.dynamic_field_has_child_object_with_ty_cost_base
    );

    let child_id = pop_arg!(args, AccountAddress).into();
    let parent = pop_arg!(args, AccountAddress).into();
    assert!(args.is_empty());
    let ty = ty_args.pop().unwrap();
    let ty_size = u64::from(ty.size());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        has_child_object_with_ty_cost_params
            .type_to_type_tag_cost_per_byte
            .mul(ty_size.into())
    );
    let tag: StructTag = match context.type_to_type_tag(&ty)? {
        TypeTag::Struct(s) => *s,
        _ => {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Sui verifier guarantees this is a struct".to_string()),
            )
        }
    };
    let struct_tag_size = u64::from(tag.abstract_size_for_gas_metering());

    native_charge_gas_early_exit!(
        context,
        gas_left,
        has_child_object_with_ty_cost_params
            .parent_child_object_exists_and_has_type_cost_per_byte
            .mul((AccountAddress::LENGTH as u64).into())
            + has_child_object_with_ty_cost_params
                .child_id_child_object_exists_and_has_type_cost_per_byte
                .mul((AccountAddress::LENGTH as u64).into())
            + has_child_object_with_ty_cost_params
                .struct_tag_child_object_exists_and_has_type_cost_per_byte
                .mul(struct_tag_size.into())
    );

    let object_runtime: &mut ObjectRuntime = context.extensions_mut().get_mut();
    let has_child = object_runtime.child_object_exists_and_has_type(
        parent,
        child_id,
        &MoveObjectType::from(tag),
    )?;
    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![Value::bool(has_child)],
    ))
}

fn get_tag_and_layout(
    context: &NativeContext,
    ty: &Type,
) -> PartialVMResult<Option<(MoveTypeLayout, StructTag)>> {
    let layout = match context.type_to_type_layout(ty)? {
        None => return Ok(None),
        Some(layout) => layout,
    };
    let tag = match context.type_to_type_tag(ty)? {
        TypeTag::Struct(s) => s,
        _ => {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Sui verifier guarantees this is a struct".to_string()),
            )
        }
    };
    Ok(Some((layout, *tag)))
}
