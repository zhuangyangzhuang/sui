// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use move_binary_format::errors::PartialVMResult;
use move_core_types::{
    gas_algebra::InternalGas,
    language_storage::TypeTag,
    value::{MoveFieldLayout, MoveStructLayout, MoveTypeLayout},
};
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type, natives::function::NativeResult, values::Value,
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};

use crate::natives::NativesCostTable;

pub(crate) fn is_otw_struct(struct_layout: &MoveStructLayout, type_tag: &TypeTag) -> bool {
    let has_one_bool_field = match struct_layout {
        MoveStructLayout::Runtime(vec) => matches!(vec.as_slice(), [MoveTypeLayout::Bool]),
        MoveStructLayout::WithFields(vec) => matches!(
            vec.as_slice(),
            [MoveFieldLayout {
                name: _,
                layout: MoveTypeLayout::Bool
            }]
        ),
        MoveStructLayout::WithTypes { type_: _, fields } => matches!(
            fields.as_slice(),
            [MoveFieldLayout {
                name: _,
                layout: MoveTypeLayout::Bool
            }]
        ),
    };

    // If a struct type has the same name as the module that defines it but capitalized, and it has
    // a single field of type bool, it means that it's a one-time witness type. The remaining
    // properties of a one-time witness type are checked in the one_time_witness_verifier pass in
    // the Sui bytecode verifier (a type with this name and with a single bool field that does not
    // have all the remaining properties of a one-time witness type will cause a verifier error).
    matches!(
        type_tag,
        TypeTag::Struct(struct_tag) if has_one_bool_field && struct_tag.name.to_string() == struct_tag.module.to_string().to_ascii_uppercase())
}

#[derive(Clone)]
pub struct TypeIsOneTimeWitnessCostParams {
    pub type_is_one_time_witness_cost_base: InternalGas,
    pub type_to_type_tag_cost_per_byte: InternalGas,
    pub type_to_type_layout_cost_per_byte: InternalGas,
    pub struct_layout_check_cost_per_byte: InternalGas,
}
/***************************************************************************************************
 * native fun derive_id
 * Implementation of the Move native function `is_one_time_witness<T: drop>(_: &T): bool`
 *   gas cost: is_one_time_witness_cost_base                        | base cost as this can be expensive oper
 *              + type_to_type_tag_cost_per_byte * ty.size()        | cost per byte of converting type to type tag
 *              + type_to_type_layout_cost_per_byte * ty.size()     | cost per byte of converting type to type layout
 *              + struct_layout_check_cost_per_byte * ty.size()     | cost per byte of checking struct via `is_otw_struct`
 **************************************************************************************************/
pub fn is_one_time_witness(
    context: &mut NativeContext,
    mut ty_args: Vec<Type>,
    args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let type_is_one_time_witness_cost_params = context
        .extensions_mut()
        .get::<NativesCostTable>()
        .type_is_one_time_witness_cost_params
        .clone();

    // unwrap safe because the interface of native function guarantees it.
    let ty = ty_args.pop().unwrap();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        type_is_one_time_witness_cost_params.type_is_one_time_witness_cost_base
    );

    let type_size: u64 = ty.size().into();

    native_charge_gas_early_exit!(
        context,
        gas_left,
        type_is_one_time_witness_cost_params
            .type_to_type_tag_cost_per_byte
            .mul(type_size.into())
    );
    let type_tag = context.type_to_type_tag(&ty)?;

    native_charge_gas_early_exit!(
        context,
        gas_left,
        type_is_one_time_witness_cost_params
            .type_to_type_layout_cost_per_byte
            .mul(type_size.into())
    );
    let type_layout = context.type_to_type_layout(&ty)?;

    let Some(MoveTypeLayout::Struct(struct_layout)) = type_layout else {
        return Ok(NativeResult::ok(native_gas_total_cost!(context, gas_left), smallvec![Value::bool(false)]))
    };

    native_charge_gas_early_exit!(
        context,
        gas_left,
        type_is_one_time_witness_cost_params
            .struct_layout_check_cost_per_byte
            .mul(type_size.into())
    );
    let is_otw = is_otw_struct(&struct_layout, &type_tag);

    Ok(NativeResult::ok(
        native_gas_total_cost!(context, gas_left),
        smallvec![Value::bool(is_otw)],
    ))
}
