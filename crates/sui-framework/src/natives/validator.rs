// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::natives::NativesCostTable;
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_core_types::{gas_algebra::InternalGas, vm_status::StatusCode};
use move_vm_runtime::{
    native_charge_gas_early_exit, native_functions::NativeContext, native_gas_total_cost,
};
use move_vm_types::{
    loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::Value,
};
use smallvec::smallvec;
use std::{collections::VecDeque, ops::Mul};
use sui_types::sui_system_state::sui_system_state_inner_v1::ValidatorMetadataV1;

pub struct ValidatorValidateMetadataBcsCostParams {
    pub metadata_validate_cost_base: InternalGas,
    pub metadata_deserialize_cost_per_byte: InternalGas,
    pub metadata_verify_cost_per_byte: InternalGas,
}
/***************************************************************************************************
 * native fun validate_metadata_bcs
 * Implementation of the Move native function `validate_metadata_bcs(metadata: vector<u8>)`
 *   gas cost: metadata_deserialize_cost_per_byte * metadata_bytes.len()           | assume cost is proportional to size
 *              + metadata_verify_cost_per_byte * metadata_bytes.len()             | assume cost is proportional to size
 *              + metadata_validate_cost_base                                      | base cost since this is an expensive oper
 **************************************************************************************************/
pub fn validate_metadata_bcs(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 1);
    let mut gas_left = context.gas_budget();
    let natvies_cost_table: &NativesCostTable = context.extensions_mut().get();
    let validate_metadata_bcs_cost_params = &natvies_cost_table.validate_metadata_bcs_cost_params;

    let metadata_bytes = pop_arg!(args, Vec<u8>);

    native_charge_gas_early_exit!(
        context,
        gas_left,
        validate_metadata_bcs_cost_params.metadata_validate_cost_base
    );

    native_charge_gas_early_exit!(
        context,
        gas_left,
        validate_metadata_bcs_cost_params
            .metadata_deserialize_cost_per_byte
            .mul((metadata_bytes.len() as u64).into())
    );

    let validator_metadata =
        bcs::from_bytes::<ValidatorMetadataV1>(&metadata_bytes).map_err(|_| {
            PartialVMError::new(StatusCode::MALFORMED).with_message(
                "ValidateMetadata Move struct does not much internal ValidateMetadata struct"
                    .to_string(),
            )
        })?;

    native_charge_gas_early_exit!(
        context,
        gas_left,
        validate_metadata_bcs_cost_params
            .metadata_verify_cost_per_byte
            .mul((metadata_bytes.len() as u64).into())
    );
    let cost = native_gas_total_cost!(context, gas_left);

    if let Result::Err(err_code) = validator_metadata.verify() {
        return Ok(NativeResult::err(cost, err_code));
    }

    Ok(NativeResult::ok(cost, smallvec![]))
}
