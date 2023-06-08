use super::multi_resource_pool::*;
use super::one_resource_pool::*;
use super::two_resource_pool::*;
use crate::errors::*;
use crate::event_schema;
use crate::kernel::kernel_api::*;
use crate::method_auth_template;
use crate::system::system_callback::*;
use crate::system::system_modules::costing::*;
use radix_engine_common::data::scrypto::*;
use radix_engine_common::types::*;
use radix_engine_interface::api::node_modules::metadata::*;
use radix_engine_interface::api::node_modules::royalty::*;
use radix_engine_interface::api::*;
use radix_engine_interface::blueprints::package::PackageDefinition;
use radix_engine_interface::blueprints::pool::*;
use radix_engine_interface::rule;
use radix_engine_interface::schema::*;
use radix_engine_interface::types::*;
use resources_tracker_macro::*;
use sbor::rust::prelude::*;
use sbor::*;

pub const POOL_MANAGER_ROLE: &'static str = "pool_manager_role";

pub struct PoolNativePackage;
impl PoolNativePackage {
    pub fn definition() -> PackageDefinition {
        // One Resource Pool
        let one_resource_pool_blueprint_schema = {
            let mut aggregator = TypeAggregator::<ScryptoCustomTypeKind>::new();

            let mut fields = Vec::new();
            fields.push(aggregator.add_child_type_and_descendents::<OneResourcePoolSubstate>());

            let collections = Vec::new();

            let mut functions = BTreeMap::new();

            functions.insert(
                ONE_RESOURCE_POOL_INSTANTIATE_IDENT.to_string(),
                FunctionSchema {
                    receiver: None,
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolInstantiateInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolInstantiateOutput>(),
                    export_name: ONE_RESOURCE_POOL_INSTANTIATE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                ONE_RESOURCE_POOL_CONTRIBUTE_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolContributeInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolContributeOutput>(),
                    export_name: ONE_RESOURCE_POOL_CONTRIBUTE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                ONE_RESOURCE_POOL_REDEEM_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolRedeemInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolRedeemOutput>(),
                    export_name: ONE_RESOURCE_POOL_REDEEM_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                ONE_RESOURCE_POOL_PROTECTED_DEPOSIT_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolProtectedDepositInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolProtectedDepositOutput>(),
                    export_name: ONE_RESOURCE_POOL_PROTECTED_DEPOSIT_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                ONE_RESOURCE_POOL_PROTECTED_WITHDRAW_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolProtectedWithdrawInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolProtectedWithdrawOutput>(),
                    export_name: ONE_RESOURCE_POOL_PROTECTED_WITHDRAW_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                ONE_RESOURCE_POOL_GET_REDEMPTION_VALUE_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref()),
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolGetRedemptionValueInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolGetRedemptionValueOutput>(
                        ),
                    export_name: ONE_RESOURCE_POOL_GET_REDEMPTION_VALUE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                ONE_RESOURCE_POOL_GET_VAULT_AMOUNT_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref()),
                    input: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolGetVaultAmountInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<OneResourcePoolGetVaultAmountOutput>(),
                    export_name: ONE_RESOURCE_POOL_GET_VAULT_AMOUNT_EXPORT_NAME.to_string(),
                },
            );

            let virtual_lazy_load_functions = BTreeMap::new();

            let event_schema = event_schema! {
                aggregator,
                [
                    super::one_resource_pool::ContributionEvent,
                    super::one_resource_pool::RedemptionEvent,
                    super::one_resource_pool::WithdrawEvent,
                    super::one_resource_pool::DepositEvent
                ]
            };

            let method_auth_template = method_auth_template! {
                // Metadata Module rules
                SchemaMethodKey::metadata(METADATA_REMOVE_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::metadata(METADATA_SET_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::metadata(METADATA_GET_IDENT) => SchemaMethodPermission::Public;

                // Royalty Module rules
                SchemaMethodKey::royalty(COMPONENT_ROYALTY_SET_ROYALTY_IDENT) => [];
                SchemaMethodKey::royalty(COMPONENT_ROYALTY_CLAIM_ROYALTIES_IDENT) => [];

                // Main Module rules
                SchemaMethodKey::main(ONE_RESOURCE_POOL_REDEEM_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(ONE_RESOURCE_POOL_GET_REDEMPTION_VALUE_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(ONE_RESOURCE_POOL_GET_VAULT_AMOUNT_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(ONE_RESOURCE_POOL_CONTRIBUTE_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::main(ONE_RESOURCE_POOL_PROTECTED_DEPOSIT_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::main(ONE_RESOURCE_POOL_PROTECTED_WITHDRAW_IDENT) => [POOL_MANAGER_ROLE];
            };

            let schema = generate_full_schema(aggregator);
            BlueprintSchema {
                outer_blueprint: None,
                schema,
                fields,
                collections,
                functions,
                virtual_lazy_load_functions,
                event_schema,
                method_auth_template,
                outer_method_auth_template: btreemap!(),
                dependencies: btreeset!(),
            }
        };

        // Two Resource Pool
        let two_resource_pool_blueprint_schema = {
            let mut aggregator = TypeAggregator::<ScryptoCustomTypeKind>::new();

            let mut fields = Vec::new();
            fields.push(aggregator.add_child_type_and_descendents::<TwoResourcePoolSubstate>());

            let collections = Vec::new();

            let mut functions = BTreeMap::new();

            functions.insert(
                TWO_RESOURCE_POOL_INSTANTIATE_IDENT.to_string(),
                FunctionSchema {
                    receiver: None,
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolInstantiateInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolInstantiateOutput>(),
                    export_name: TWO_RESOURCE_POOL_INSTANTIATE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                TWO_RESOURCE_POOL_CONTRIBUTE_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolContributeInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolContributeOutput>(),
                    export_name: TWO_RESOURCE_POOL_CONTRIBUTE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                TWO_RESOURCE_POOL_REDEEM_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolRedeemInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolRedeemOutput>(),
                    export_name: TWO_RESOURCE_POOL_REDEEM_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                TWO_RESOURCE_POOL_PROTECTED_DEPOSIT_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolProtectedDepositInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolProtectedDepositOutput>(),
                    export_name: TWO_RESOURCE_POOL_PROTECTED_DEPOSIT_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                TWO_RESOURCE_POOL_PROTECTED_WITHDRAW_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolProtectedWithdrawInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolProtectedWithdrawOutput>(),
                    export_name: TWO_RESOURCE_POOL_PROTECTED_WITHDRAW_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                TWO_RESOURCE_POOL_GET_REDEMPTION_VALUE_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref()),
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolGetRedemptionValueInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolGetRedemptionValueOutput>(
                        ),
                    export_name: TWO_RESOURCE_POOL_GET_REDEMPTION_VALUE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                TWO_RESOURCE_POOL_GET_VAULT_AMOUNTS_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref()),
                    input: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolGetVaultAmountsInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<TwoResourcePoolGetVaultAmountsOutput>(),
                    export_name: TWO_RESOURCE_POOL_GET_VAULT_AMOUNTS_EXPORT_NAME.to_string(),
                },
            );

            let virtual_lazy_load_functions = BTreeMap::new();

            let event_schema = event_schema! {
                aggregator,
                [
                    super::two_resource_pool::ContributionEvent,
                    super::two_resource_pool::RedemptionEvent,
                    super::two_resource_pool::WithdrawEvent,
                    super::two_resource_pool::DepositEvent
                ]
            };

            let method_auth_template = method_auth_template! {
                // Metadata Module rules
                SchemaMethodKey::metadata(METADATA_REMOVE_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::metadata(METADATA_SET_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::metadata(METADATA_GET_IDENT) => SchemaMethodPermission::Public;

                // Royalty Module rules
                SchemaMethodKey::royalty(COMPONENT_ROYALTY_SET_ROYALTY_IDENT) => [];
                SchemaMethodKey::royalty(COMPONENT_ROYALTY_CLAIM_ROYALTIES_IDENT) => [];

                // Main Module rules
                SchemaMethodKey::main(TWO_RESOURCE_POOL_REDEEM_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(TWO_RESOURCE_POOL_GET_REDEMPTION_VALUE_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(TWO_RESOURCE_POOL_GET_VAULT_AMOUNTS_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(TWO_RESOURCE_POOL_CONTRIBUTE_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::main(TWO_RESOURCE_POOL_PROTECTED_DEPOSIT_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::main(TWO_RESOURCE_POOL_PROTECTED_WITHDRAW_IDENT) => [POOL_MANAGER_ROLE];
            };

            let schema = generate_full_schema(aggregator);
            BlueprintSchema {
                outer_blueprint: None,
                schema,
                fields,
                collections,
                functions,
                virtual_lazy_load_functions,
                event_schema,
                method_auth_template,
                outer_method_auth_template: btreemap!(),
                dependencies: btreeset!(),
            }
        };

        // Multi Resource Pool
        let multi_resource_pool_blueprint_schema = {
            let mut aggregator = TypeAggregator::<ScryptoCustomTypeKind>::new();

            let mut fields = Vec::new();
            fields.push(aggregator.add_child_type_and_descendents::<MultiResourcePoolSubstate>());

            let collections = Vec::new();

            let mut functions = BTreeMap::new();

            functions.insert(
                MULTI_RESOURCE_POOL_INSTANTIATE_IDENT.to_string(),
                FunctionSchema {
                    receiver: None,
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolInstantiateInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolInstantiateOutput>(),
                    export_name: MULTI_RESOURCE_POOL_INSTANTIATE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                MULTI_RESOURCE_POOL_CONTRIBUTE_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolContributeInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolContributeOutput>(),
                    export_name: MULTI_RESOURCE_POOL_CONTRIBUTE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                MULTI_RESOURCE_POOL_REDEEM_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolRedeemInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolRedeemOutput>(),
                    export_name: MULTI_RESOURCE_POOL_REDEEM_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                MULTI_RESOURCE_POOL_PROTECTED_DEPOSIT_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolProtectedDepositInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolProtectedDepositOutput>(
                        ),
                    export_name: MULTI_RESOURCE_POOL_PROTECTED_DEPOSIT_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                MULTI_RESOURCE_POOL_PROTECTED_WITHDRAW_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref_mut()),
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolProtectedWithdrawInput>(
                        ),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolProtectedWithdrawOutput>(
                        ),
                    export_name: MULTI_RESOURCE_POOL_PROTECTED_WITHDRAW_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                MULTI_RESOURCE_POOL_GET_REDEMPTION_VALUE_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref()),
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolGetRedemptionValueInput>(
                        ),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolGetRedemptionValueOutput>(
                        ),
                    export_name: MULTI_RESOURCE_POOL_GET_REDEMPTION_VALUE_EXPORT_NAME.to_string(),
                },
            );

            functions.insert(
                MULTI_RESOURCE_POOL_GET_VAULT_AMOUNTS_IDENT.to_string(),
                FunctionSchema {
                    receiver: Some(ReceiverInfo::normal_ref()),
                    input: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolGetVaultAmountsInput>(),
                    output: aggregator
                        .add_child_type_and_descendents::<MultiResourcePoolGetVaultAmountsOutput>(),
                    export_name: MULTI_RESOURCE_POOL_GET_VAULT_AMOUNTS_EXPORT_NAME.to_string(),
                },
            );

            let virtual_lazy_load_functions = BTreeMap::new();

            let event_schema = event_schema! {
                aggregator,
                [
                    super::multi_resource_pool::ContributionEvent,
                    super::multi_resource_pool::RedemptionEvent,
                    super::multi_resource_pool::WithdrawEvent,
                    super::multi_resource_pool::DepositEvent
                ]
            };

            let method_auth_template = method_auth_template! {
                // Metadata Module rules
                SchemaMethodKey::metadata(METADATA_REMOVE_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::metadata(METADATA_SET_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::metadata(METADATA_GET_IDENT) => SchemaMethodPermission::Public;

                // Royalty Module rules
                SchemaMethodKey::royalty(COMPONENT_ROYALTY_CLAIM_ROYALTIES_IDENT) => [];
                SchemaMethodKey::royalty(COMPONENT_ROYALTY_SET_ROYALTY_IDENT) => [];

                // Main Module rules
                SchemaMethodKey::main(MULTI_RESOURCE_POOL_REDEEM_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(MULTI_RESOURCE_POOL_GET_REDEMPTION_VALUE_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(MULTI_RESOURCE_POOL_GET_VAULT_AMOUNTS_IDENT) => SchemaMethodPermission::Public;
                SchemaMethodKey::main(MULTI_RESOURCE_POOL_CONTRIBUTE_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::main(MULTI_RESOURCE_POOL_PROTECTED_DEPOSIT_IDENT) => [POOL_MANAGER_ROLE];
                SchemaMethodKey::main(MULTI_RESOURCE_POOL_PROTECTED_WITHDRAW_IDENT) => [POOL_MANAGER_ROLE];
            };

            let schema = generate_full_schema(aggregator);
            BlueprintSchema {
                outer_blueprint: None,
                schema,
                fields,
                collections,
                functions,
                virtual_lazy_load_functions,
                event_schema,
                method_auth_template,
                outer_method_auth_template: btreemap!(),
                dependencies: btreeset!(),
            }
        };

        let schema = PackageSchema {
            blueprints: btreemap!(
                ONE_RESOURCE_POOL_BLUEPRINT_IDENT.to_string() => one_resource_pool_blueprint_schema,
                TWO_RESOURCE_POOL_BLUEPRINT_IDENT.to_string() => two_resource_pool_blueprint_schema,
                MULTI_RESOURCE_POOL_BLUEPRINT_IDENT.to_string() => multi_resource_pool_blueprint_schema
            ),
        };

        let function_access_rules = btreemap!(
            ONE_RESOURCE_POOL_BLUEPRINT_IDENT.to_string() => btreemap!(
                ONE_RESOURCE_POOL_INSTANTIATE_IDENT.to_string() => rule!(allow_all),
            ),
            TWO_RESOURCE_POOL_BLUEPRINT_IDENT.to_string() => btreemap!(
                TWO_RESOURCE_POOL_INSTANTIATE_IDENT.to_string() => rule!(allow_all),
            ),
            MULTI_RESOURCE_POOL_BLUEPRINT_IDENT.to_string() => btreemap!(
                MULTI_RESOURCE_POOL_INSTANTIATE_IDENT.to_string() => rule!(allow_all),
            )
        );

        PackageDefinition {
            schema,
            function_access_rules,
            royalty_config: btreemap!(),
        }
    }

    #[trace_resources(log=export_name)]
    pub fn invoke_export<Y>(
        export_name: &str,
        receiver: Option<&NodeId>,
        input: &IndexedScryptoValue,
        api: &mut Y,
    ) -> Result<IndexedScryptoValue, RuntimeError>
    where
        Y: KernelNodeApi + KernelSubstateApi<SystemLockData> + ClientApi<RuntimeError>,
    {
        match export_name {
            ONE_RESOURCE_POOL_INSTANTIATE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolInstantiateInput {
                    resource_address,
                    pool_manager_rule,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = OneResourcePoolBlueprint::instantiate(
                    resource_address,
                    pool_manager_rule,
                    api,
                )?;

                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            ONE_RESOURCE_POOL_CONTRIBUTE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolContributeInput { bucket } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = OneResourcePoolBlueprint::contribute(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            ONE_RESOURCE_POOL_REDEEM_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolRedeemInput { bucket } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = OneResourcePoolBlueprint::redeem(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            ONE_RESOURCE_POOL_PROTECTED_DEPOSIT_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolProtectedDepositInput { bucket } =
                    input.as_typed().map_err(|e| {
                        RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                    })?;
                let rtn = OneResourcePoolBlueprint::protected_deposit(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            ONE_RESOURCE_POOL_PROTECTED_WITHDRAW_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolProtectedWithdrawInput { amount } =
                    input.as_typed().map_err(|e| {
                        RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                    })?;
                let rtn = OneResourcePoolBlueprint::protected_withdraw(amount, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            ONE_RESOURCE_POOL_GET_REDEMPTION_VALUE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolGetRedemptionValueInput {
                    amount_of_pool_units,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn =
                    OneResourcePoolBlueprint::get_redemption_value(amount_of_pool_units, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            ONE_RESOURCE_POOL_GET_VAULT_AMOUNT_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let OneResourcePoolGetVaultAmountInput {} = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = OneResourcePoolBlueprint::get_vault_amount(api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_INSTANTIATE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolInstantiateInput {
                    resource_addresses,
                    pool_manager_rule,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = TwoResourcePoolBlueprint::instantiate(
                    resource_addresses,
                    pool_manager_rule,
                    api,
                )?;

                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_CONTRIBUTE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolContributeInput { buckets } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = TwoResourcePoolBlueprint::contribute(buckets, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_REDEEM_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolRedeemInput { bucket } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = TwoResourcePoolBlueprint::redeem(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_PROTECTED_DEPOSIT_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolProtectedDepositInput { bucket } =
                    input.as_typed().map_err(|e| {
                        RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                    })?;
                let rtn = TwoResourcePoolBlueprint::protected_deposit(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_PROTECTED_WITHDRAW_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolProtectedWithdrawInput {
                    amount,
                    resource_address,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn =
                    TwoResourcePoolBlueprint::protected_withdraw(resource_address, amount, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_GET_REDEMPTION_VALUE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolGetRedemptionValueInput {
                    amount_of_pool_units,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn =
                    TwoResourcePoolBlueprint::get_redemption_value(amount_of_pool_units, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            TWO_RESOURCE_POOL_GET_VAULT_AMOUNTS_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let TwoResourcePoolGetVaultAmountsInput {} = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = TwoResourcePoolBlueprint::get_vault_amounts(api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_INSTANTIATE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolInstantiateInput {
                    resource_addresses,
                    pool_manager_rule,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = MultiResourcePoolBlueprint::instantiate(
                    resource_addresses,
                    pool_manager_rule,
                    api,
                )?;

                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_CONTRIBUTE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolContributeInput { buckets } =
                    input.as_typed().map_err(|e| {
                        RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                    })?;
                let rtn = MultiResourcePoolBlueprint::contribute(buckets, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_REDEEM_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolRedeemInput { bucket } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = MultiResourcePoolBlueprint::redeem(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_PROTECTED_DEPOSIT_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolProtectedDepositInput { bucket } =
                    input.as_typed().map_err(|e| {
                        RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                    })?;
                let rtn = MultiResourcePoolBlueprint::protected_deposit(bucket, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_PROTECTED_WITHDRAW_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolProtectedWithdrawInput {
                    amount,
                    resource_address,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn =
                    MultiResourcePoolBlueprint::protected_withdraw(resource_address, amount, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_GET_REDEMPTION_VALUE_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolGetRedemptionValueInput {
                    amount_of_pool_units,
                } = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn =
                    MultiResourcePoolBlueprint::get_redemption_value(amount_of_pool_units, api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            MULTI_RESOURCE_POOL_GET_VAULT_AMOUNTS_EXPORT_NAME => {
                api.consume_cost_units(FIXED_LOW_FEE, ClientCostingReason::RunNative)?;

                let MultiResourcePoolGetVaultAmountsInput {} = input.as_typed().map_err(|e| {
                    RuntimeError::SystemUpstreamError(SystemUpstreamError::InputDecodeError(e))
                })?;
                let rtn = MultiResourcePoolBlueprint::get_vault_amounts(api)?;
                Ok(IndexedScryptoValue::from_typed(&rtn))
            }

            _ => Err(RuntimeError::SystemUpstreamError(
                SystemUpstreamError::NativeExportDoesNotExist(export_name.to_string()),
            )),
        }
    }
}
