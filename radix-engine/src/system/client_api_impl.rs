use crate::blueprints::access_controller::AccessControllerSubstate;
use crate::blueprints::account::AccountSubstate;
use crate::blueprints::clock::CurrentTimeRoundedToMinutesSubstate;
use crate::blueprints::epoch_manager::{
    EpochManagerSubstate, ValidatorSetSubstate, ValidatorSubstate,
};
use crate::blueprints::event_store::EventStoreNativePackage;
use crate::blueprints::logger::LoggerNativePackage;
use crate::blueprints::resource::{
    BucketInfoSubstate, FungibleProof, NonFungibleProof, NonFungibleSubstate, ProofInfoSubstate,
    ResourceManagerSubstate, VaultInfoSubstate,
};
use crate::errors::RuntimeError;
use crate::errors::{KernelError, SystemError};
use crate::kernel::actor::ActorIdentifier;
use crate::kernel::kernel::Kernel;
use crate::kernel::kernel_api::KernelNodeApi;
use crate::kernel::kernel_api::KernelSubstateApi;
use crate::kernel::kernel_api::{Invokable, KernelInternalApi};
use crate::kernel::module::KernelModule;
use crate::kernel::module_mixer::KernelModuleMixer;
use crate::system::node::RENodeInit;
use crate::system::node::RENodeModuleInit;
use crate::system::node_modules::access_rules::MethodAccessRulesSubstate;
use crate::system::node_modules::metadata::MetadataSubstate;
use crate::system::node_modules::type_info::{TypeInfoBlueprint, TypeInfoSubstate};
use crate::system::node_substates::RuntimeSubstate;
use crate::system::package::Package;
use crate::types::*;
use crate::wasm::WasmEngine;
use radix_engine_interface::api::component::{
    ComponentRoyaltyAccumulatorSubstate, ComponentRoyaltyConfigSubstate, ComponentStateSubstate,
    KeyValueStoreEntrySubstate,
};
use radix_engine_interface::api::node_modules::auth::*;
use radix_engine_interface::api::node_modules::metadata::*;
use radix_engine_interface::api::node_modules::royalty::*;
use radix_engine_interface::api::package::*;
use radix_engine_interface::api::substate_api::LockFlags;
use radix_engine_interface::api::unsafe_api::ClientCostingReason;
use radix_engine_interface::api::ClientEventApi;
use radix_engine_interface::api::{types::*, ClientLoggerApi};
use radix_engine_interface::api::{
    ClientActorApi, ClientApi, ClientNodeApi, ClientObjectApi, ClientPackageApi, ClientSubstateApi,
    ClientUnsafeApi,
};
use radix_engine_interface::blueprints::access_controller::*;
use radix_engine_interface::blueprints::account::*;
use radix_engine_interface::blueprints::epoch_manager::*;
use radix_engine_interface::blueprints::identity::*;
use radix_engine_interface::blueprints::logger::Level;
use radix_engine_interface::blueprints::resource::*;
use radix_engine_interface::data::model::Own;
use radix_engine_interface::data::*;
use sbor::rust::string::ToString;
use sbor::rust::vec::Vec;

impl<'g, 's, W> ClientNodeApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn sys_drop_node(&mut self, node_id: RENodeId) -> Result<(), RuntimeError> {
        self.kernel_drop_node(node_id)?;
        Ok(())
    }
}

impl<'g, 's, W> ClientSubstateApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn sys_lock_substate(
        &mut self,
        node_id: RENodeId,
        offset: SubstateOffset,
        flags: LockFlags,
    ) -> Result<LockHandle, RuntimeError> {
        if flags.contains(LockFlags::UNMODIFIED_BASE) || flags.contains(LockFlags::FORCE_WRITE) {
            let (package_address, blueprint) = self.get_object_type_info(node_id)?;
            if !matches!(
                (package_address, blueprint.as_str()),
                (RESOURCE_MANAGER_PACKAGE, VAULT_BLUEPRINT)
            ) {
                return Err(RuntimeError::SystemError(SystemError::InvalidLockFlags));
            }
        }

        let module_id = if let ActorIdentifier::Method(method) =
            self.kernel_get_current_actor().unwrap().identifier
        {
            method.1
        } else {
            // TODO: Remove this
            NodeModuleId::SELF
        };

        self.kernel_lock_substate(node_id, module_id, offset, flags)
    }

    fn sys_read_substate(&mut self, lock_handle: LockHandle) -> Result<Vec<u8>, RuntimeError> {
        self.kernel_read_substate(lock_handle).map(|v| v.into())
    }

    fn sys_write_substate(
        &mut self,
        lock_handle: LockHandle,
        buffer: Vec<u8>,
    ) -> Result<(), RuntimeError> {
        let offset = self.kernel_get_lock_info(lock_handle)?.offset;
        let substate = RuntimeSubstate::decode_from_buffer(&offset, &buffer)?;

        match substate {
            RuntimeSubstate::ComponentState(next) => {
                let state: &mut ComponentStateSubstate =
                    self.kernel_get_substate_ref_mut(lock_handle)?;
                *state = next
            }
            RuntimeSubstate::KeyValueStoreEntry(next) => {
                let entry: &mut KeyValueStoreEntrySubstate =
                    self.kernel_get_substate_ref_mut(lock_handle)?;
                *entry = next;
            }
            RuntimeSubstate::NonFungible(next) => {
                let non_fungible: &mut NonFungibleSubstate =
                    self.kernel_get_substate_ref_mut(lock_handle)?;
                *non_fungible = next;
            }
            _ => return Err(RuntimeError::KernelError(KernelError::InvalidOverwrite)),
        }

        Ok(())
    }

    fn sys_drop_lock(&mut self, lock_handle: LockHandle) -> Result<(), RuntimeError> {
        let info = self.kernel_get_lock_info(lock_handle)?;
        if info.flags.contains(LockFlags::MUTABLE) {}

        self.kernel_drop_lock(lock_handle)
    }
}

impl<'g, 's, W> ClientActorApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn get_fn_identifier(&mut self) -> Result<FnIdentifier, RuntimeError> {
        Ok(self.kernel_get_current_actor().unwrap().fn_identifier)
    }
}

impl<'g, 's, W> ClientPackageApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn new_package(
        &mut self,
        code: Vec<u8>,
        abi: BTreeMap<String, BlueprintAbi>,
        access_rules: AccessRules,
        royalty_config: BTreeMap<String, RoyaltyConfig>,
        metadata: BTreeMap<String, String>,
    ) -> Result<PackageAddress, RuntimeError> {
        let result = self.call_function(
            PACKAGE_LOADER,
            PACKAGE_LOADER_BLUEPRINT,
            PACKAGE_LOADER_PUBLISH_WASM_IDENT,
            scrypto_encode(&PackageLoaderPublishWasmInput {
                package_address: None,
                code,
                abi,
                access_rules,
                royalty_config,
                metadata,
            })
            .unwrap(),
        )?;

        let package_address: PackageAddress = scrypto_decode(&result).unwrap();
        Ok(package_address)
    }

    fn call_function(
        &mut self,
        package_address: PackageAddress,
        blueprint_name: &str,
        function_name: &str,
        args: Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeError> {
        let invocation = FunctionInvocation {
            fn_identifier: FnIdentifier::new(
                package_address,
                blueprint_name.to_string(),
                function_name.to_string(),
            ),
            args,
        };

        self.kernel_invoke(invocation)
            .map(|v| scrypto_encode(&v).expect("Failed to encode scrypto fn return"))
    }

    fn get_code(&mut self, package_address: PackageAddress) -> Result<PackageCode, RuntimeError> {
        let handle = self.kernel_lock_substate(
            RENodeId::GlobalPackage(package_address),
            NodeModuleId::SELF,
            SubstateOffset::Package(PackageOffset::Code),
            LockFlags::read_only(),
        )?;
        let package: &PackageCodeSubstate = self.kernel_get_substate_ref(handle)?;
        let code = package.code().to_vec();
        self.kernel_drop_lock(handle)?;
        Ok(PackageCode::Wasm(code))
    }

    fn get_abi(
        &mut self,
        package_address: PackageAddress,
    ) -> Result<BTreeMap<String, BlueprintAbi>, RuntimeError> {
        let handle = self.kernel_lock_substate(
            RENodeId::GlobalPackage(package_address),
            NodeModuleId::SELF,
            SubstateOffset::Package(PackageOffset::Info),
            LockFlags::read_only(),
        )?;
        let package: &PackageInfoSubstate = self.kernel_get_substate_ref(handle)?;
        let abi = package.blueprint_abis.clone();
        self.kernel_drop_lock(handle)?;
        Ok(abi)
    }
}

impl<'g, 's, W> ClientObjectApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn new_object(
        &mut self,
        blueprint_ident: &str,
        mut app_states: BTreeMap<u8, Vec<u8>>,
    ) -> Result<ObjectId, RuntimeError> {
        // Create component RENode
        // FIXME: support native blueprints
        let package_address = self
            .kernel_get_current_actor()
            .unwrap()
            .fn_identifier
            .package_address();

        let (node_id, node_init) = match package_address {
            RESOURCE_MANAGER_PACKAGE => match blueprint_ident {
                RESOURCE_MANAGER_BLUEPRINT => {
                    let substate_bytes = app_states.into_iter().next().unwrap().1;
                    let substate: ResourceManagerSubstate = scrypto_decode(&substate_bytes)
                        .map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                    (
                        node_id,
                        RENodeInit::Object(btreemap!(
                            SubstateOffset::ResourceManager(ResourceManagerOffset::ResourceManager) => RuntimeSubstate::ResourceManager(substate)
                        )),
                    )
                }
                PROOF_BLUEPRINT => {
                    let substate_bytes_0 = app_states.remove(&0u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let substate_bytes_1 = app_states.remove(&1u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let proof_info_substate: ProofInfoSubstate = scrypto_decode(&substate_bytes_0)
                        .map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;

                    let node_init = match proof_info_substate.resource_type {
                        ResourceType::NonFungible { .. } => {
                            let non_fungible_proof: NonFungibleProof =
                                scrypto_decode(&substate_bytes_1).map_err(|_| {
                                    RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                                })?;

                            RENodeInit::Object(btreemap!(
                                SubstateOffset::Proof(ProofOffset::Info) => RuntimeSubstate::ProofInfo(proof_info_substate),
                                SubstateOffset::Proof(ProofOffset::NonFungible) => RuntimeSubstate::NonFungibleProof(non_fungible_proof),
                            ))
                        }
                        ResourceType::Fungible { .. } => {
                            let fungible_proof: FungibleProof = scrypto_decode(&substate_bytes_1)
                                .map_err(|_| {
                                RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                            })?;
                            RENodeInit::Object(btreemap!(
                                SubstateOffset::Proof(ProofOffset::Info) => RuntimeSubstate::ProofInfo(proof_info_substate),
                                SubstateOffset::Proof(ProofOffset::Fungible) => RuntimeSubstate::FungibleProof(fungible_proof),
                            ))
                        }
                    };

                    (node_id, node_init)
                }
                BUCKET_BLUEPRINT => {
                    let substate_bytes_0 = app_states.remove(&0u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let substate_bytes_1 = app_states.remove(&1u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let bucket_info_substate: BucketInfoSubstate =
                        scrypto_decode(&substate_bytes_0).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;

                    let node_init = match bucket_info_substate.resource_type {
                        ResourceType::NonFungible { .. } => {
                            let liquid_resource: LiquidNonFungibleResource =
                                scrypto_decode(&substate_bytes_1).map_err(|_| {
                                    RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                                })?;

                            RENodeInit::Object(btreemap!(
                                SubstateOffset::Bucket(BucketOffset::Info) => RuntimeSubstate::BucketInfo(bucket_info_substate),
                                SubstateOffset::Bucket(BucketOffset::LiquidNonFungible) => RuntimeSubstate::BucketLiquidNonFungible(liquid_resource),
                                SubstateOffset::Bucket(BucketOffset::LockedNonFungible) => RuntimeSubstate::BucketLockedNonFungible(LockedNonFungibleResource::new_empty()),
                            ))
                        }
                        ResourceType::Fungible { .. } => {
                            let liquid_resource: LiquidFungibleResource =
                                scrypto_decode(&substate_bytes_1).map_err(|_| {
                                    RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                                })?;

                            RENodeInit::Object(btreemap!(
                                SubstateOffset::Bucket(BucketOffset::Info) => RuntimeSubstate::BucketInfo(bucket_info_substate),
                                SubstateOffset::Bucket(BucketOffset::LiquidFungible) => RuntimeSubstate::BucketLiquidFungible(liquid_resource),
                                SubstateOffset::Bucket(BucketOffset::LockedFungible) => RuntimeSubstate::BucketLockedFungible(LockedFungibleResource::new_empty()),
                            ))
                        }
                    };

                    (node_id, node_init)
                }
                VAULT_BLUEPRINT => {
                    let substate_bytes_0 = app_states.remove(&0u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let substate_bytes_1 = app_states.remove(&1u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let vault_info_substate: VaultInfoSubstate = scrypto_decode(&substate_bytes_0)
                        .map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;

                    let node_init = match vault_info_substate.resource_type {
                        ResourceType::NonFungible { .. } => {
                            let liquid_resource: LiquidNonFungibleResource =
                                scrypto_decode(&substate_bytes_1).map_err(|_| {
                                    RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                                })?;

                            RENodeInit::Object(btreemap!(
                                SubstateOffset::Vault(VaultOffset::Info) => RuntimeSubstate::VaultInfo(vault_info_substate),
                                SubstateOffset::Vault(VaultOffset::LiquidNonFungible) => RuntimeSubstate::VaultLiquidNonFungible(liquid_resource),
                                SubstateOffset::Vault(VaultOffset::LockedNonFungible) => RuntimeSubstate::VaultLockedNonFungible(LockedNonFungibleResource::new_empty()),
                            ))
                        }
                        ResourceType::Fungible { .. } => {
                            let liquid_resource: LiquidFungibleResource =
                                scrypto_decode(&substate_bytes_1).map_err(|_| {
                                    RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                                })?;

                            RENodeInit::Object(btreemap!(
                                SubstateOffset::Vault(VaultOffset::Info) => RuntimeSubstate::VaultInfo(vault_info_substate),
                                SubstateOffset::Vault(VaultOffset::LiquidFungible) => RuntimeSubstate::VaultLiquidFungible(liquid_resource),
                                SubstateOffset::Vault(VaultOffset::LockedFungible) => RuntimeSubstate::VaultLockedFungible(LockedFungibleResource::new_empty()),
                            ))
                        }
                    };

                    (node_id, node_init)
                }
                _ => return Err(RuntimeError::SystemError(SystemError::BlueprintNotFound)),
            },
            METADATA_PACKAGE => {
                let substate_bytes_0 = app_states.remove(&0u8).ok_or(RuntimeError::SystemError(
                    SystemError::ObjectDoesNotMatchSchema,
                ))?;

                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }

                let substate: MetadataSubstate =
                    scrypto_decode(&substate_bytes_0).map_err(|_| {
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                    })?;

                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                (
                    node_id,
                    RENodeInit::Object(btreemap!(
                        SubstateOffset::Metadata(MetadataOffset::Metadata) => RuntimeSubstate::Metadata(substate),
                    )),
                )
            }
            ROYALTY_PACKAGE => match blueprint_ident {
                COMPONENT_ROYALTY_BLUEPRINT => {
                    let substate_bytes_0 = app_states.remove(&0u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let substate_bytes_1 = app_states.remove(&1u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;

                    if !app_states.is_empty() {
                        return Err(RuntimeError::SystemError(
                            SystemError::ObjectDoesNotMatchSchema,
                        ));
                    }

                    let config_substate: ComponentRoyaltyConfigSubstate =
                        scrypto_decode(&substate_bytes_0).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;
                    let accumulator_substate: ComponentRoyaltyAccumulatorSubstate =
                        scrypto_decode(&substate_bytes_1).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                    (
                        node_id,
                        RENodeInit::Object(btreemap!(
                            SubstateOffset::Royalty(RoyaltyOffset::RoyaltyConfig) => RuntimeSubstate::ComponentRoyaltyConfig(config_substate),
                            SubstateOffset::Royalty(RoyaltyOffset::RoyaltyAccumulator) => RuntimeSubstate::ComponentRoyaltyAccumulator(accumulator_substate)
                        )),
                    )
                }
                _ => return Err(RuntimeError::SystemError(SystemError::BlueprintNotFound)),
            },
            ACCESS_RULES_PACKAGE => {
                let substate_bytes_0 = app_states.remove(&0u8).ok_or(RuntimeError::SystemError(
                    SystemError::ObjectDoesNotMatchSchema,
                ))?;

                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }

                let substate: MethodAccessRulesSubstate = scrypto_decode(&substate_bytes_0)
                    .map_err(|_| {
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                    })?;

                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                (
                    node_id,
                    RENodeInit::Object(btreemap!(
                        SubstateOffset::AccessRules(AccessRulesOffset::AccessRules) => RuntimeSubstate::MethodAccessRules(substate)
                    )),
                )
            }
            EPOCH_MANAGER_PACKAGE => match blueprint_ident {
                VALIDATOR_BLUEPRINT => {
                    let substate_bytes_0 = app_states.remove(&0u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;

                    if !app_states.is_empty() {
                        return Err(RuntimeError::SystemError(
                            SystemError::ObjectDoesNotMatchSchema,
                        ));
                    }

                    let substate: ValidatorSubstate =
                        scrypto_decode(&substate_bytes_0).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                    (
                        node_id,
                        RENodeInit::Object(btreemap!(
                            SubstateOffset::Validator(ValidatorOffset::Validator) => RuntimeSubstate::Validator(substate)
                        )),
                    )
                }
                EPOCH_MANAGER_BLUEPRINT => {
                    let substate_bytes_0 = app_states.remove(&0u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let substate_bytes_1 = app_states.remove(&1u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;
                    let substate_bytes_2 = app_states.remove(&2u8).ok_or(
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema),
                    )?;

                    if !app_states.is_empty() {
                        return Err(RuntimeError::SystemError(
                            SystemError::ObjectDoesNotMatchSchema,
                        ));
                    }

                    let epoch_mgr_substate: EpochManagerSubstate =
                        scrypto_decode(&substate_bytes_0).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;
                    let validator_set_substate_0: ValidatorSetSubstate =
                        scrypto_decode(&substate_bytes_1).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;
                    let validator_set_substate_1: ValidatorSetSubstate =
                        scrypto_decode(&substate_bytes_2).map_err(|_| {
                            RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                        })?;

                    let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                    (
                        node_id,
                        RENodeInit::Object(btreemap!(
                            SubstateOffset::EpochManager(EpochManagerOffset::EpochManager) => RuntimeSubstate::EpochManager(epoch_mgr_substate),
                            SubstateOffset::EpochManager(EpochManagerOffset::CurrentValidatorSet) => RuntimeSubstate::ValidatorSet(validator_set_substate_0),
                            SubstateOffset::EpochManager(EpochManagerOffset::PreparingValidatorSet) => RuntimeSubstate::ValidatorSet(validator_set_substate_1)
                        )),
                    )
                }
                _ => return Err(RuntimeError::SystemError(SystemError::BlueprintNotFound)),
            },
            ACCESS_CONTROLLER_PACKAGE => {
                let substate_bytes_0 = app_states.remove(&0u8).ok_or(RuntimeError::SystemError(
                    SystemError::ObjectDoesNotMatchSchema,
                ))?;
                let substate: AccessControllerSubstate = scrypto_decode(&substate_bytes_0)
                    .map_err(|_| {
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                    })?;

                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }

                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                (
                    node_id,
                    RENodeInit::Object(btreemap!(
                        SubstateOffset::AccessController(AccessControllerOffset::AccessController)
                            => RuntimeSubstate::AccessController(substate)
                    )),
                )
            }
            IDENTITY_PACKAGE => {
                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }

                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                (node_id, RENodeInit::Object(btreemap!()))
            }
            ACCOUNT_PACKAGE => {
                let substate_bytes_0 = app_states.remove(&0u8).ok_or(RuntimeError::SystemError(
                    SystemError::ObjectDoesNotMatchSchema,
                ))?;
                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }
                let substate: AccountSubstate =
                    scrypto_decode(&substate_bytes_0).map_err(|_| {
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                    })?;

                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                (
                    node_id,
                    RENodeInit::Object(btreemap!(
                        SubstateOffset::Account(AccountOffset::Account)
                            => RuntimeSubstate::Account(substate)
                    )),
                )
            }
            CLOCK_PACKAGE => {
                let substate_bytes_0 = app_states.remove(&0u8).ok_or(RuntimeError::SystemError(
                    SystemError::ObjectDoesNotMatchSchema,
                ))?;
                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }
                let substate: CurrentTimeRoundedToMinutesSubstate =
                    scrypto_decode(&substate_bytes_0).map_err(|_| {
                        RuntimeError::SystemError(SystemError::ObjectDoesNotMatchSchema)
                    })?;

                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;
                (
                    node_id,
                    RENodeInit::Object(btreemap!(
                        SubstateOffset::Clock(ClockOffset::CurrentTimeRoundedToMinutes)
                            => RuntimeSubstate::CurrentTimeRoundedToMinutes(substate)
                    )),
                )
            }
            _ => {
                let abi = Package::get_blueprint_abi(
                    RENodeId::GlobalPackage(package_address),
                    blueprint_ident.to_string(),
                    self,
                )?;

                let substate_bytes_0 = app_states.remove(&0u8).ok_or(RuntimeError::SystemError(
                    SystemError::ObjectDoesNotMatchSchema,
                ))?;

                if !app_states.is_empty() {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }

                let substate: ScryptoValue = scrypto_decode(&substate_bytes_0)
                    .map_err(|e| RuntimeError::SystemError(SystemError::InvalidScryptoValue(e)))?;

                if !match_schema_with_value(&abi.structure, &substate) {
                    return Err(RuntimeError::SystemError(
                        SystemError::ObjectDoesNotMatchSchema,
                    ));
                }

                // Allocate node id
                let node_id = self.kernel_allocate_node_id(RENodeType::Object)?;

                (
                    node_id,
                    RENodeInit::Object(btreemap!(
                        SubstateOffset::Component(ComponentOffset::State0)
                        => RuntimeSubstate::ComponentState(ComponentStateSubstate::new(substate_bytes_0))
                    )),
                )
            }
        };

        self.kernel_create_node(
            node_id,
            node_init,
            btreemap!(
                NodeModuleId::TypeInfo => RENodeModuleInit::TypeInfo(
                    TypeInfoSubstate::new(package_address, blueprint_ident.to_string(), false)
                ),
            ),
        )?;

        Ok(node_id.into())
    }

    fn globalize(
        &mut self,
        node_id: RENodeId,
        modules: BTreeMap<NodeModuleId, Vec<u8>>,
    ) -> Result<Address, RuntimeError> {
        let node_type = match node_id {
            RENodeId::Object(..) => {
                let (package_address, blueprint) = TypeInfoBlueprint::get_type(node_id, self)?;
                match (package_address, blueprint.as_str()) {
                    (ACCOUNT_PACKAGE, ACCOUNT_BLUEPRINT) => RENodeType::GlobalAccount,
                    (IDENTITY_PACKAGE, IDENTITY_BLUEPRINT) => RENodeType::GlobalIdentity,
                    (ACCESS_CONTROLLER_PACKAGE, ACCESS_CONTROLLER_BLUEPRINT) => {
                        RENodeType::GlobalAccessController
                    }
                    (EPOCH_MANAGER_PACKAGE, VALIDATOR_BLUEPRINT) => RENodeType::GlobalValidator,
                    _ => RENodeType::GlobalComponent,
                }
            }
            _ => return Err(RuntimeError::SystemError(SystemError::CannotGlobalize)),
        };

        let global_node_id = self.kernel_allocate_node_id(node_type)?;
        self.globalize_with_address(node_id, modules, global_node_id.into())
    }

    fn globalize_with_address(
        &mut self,
        node_id: RENodeId,
        modules: BTreeMap<NodeModuleId, Vec<u8>>,
        address: Address,
    ) -> Result<Address, RuntimeError> {
        let node = self.kernel_drop_node(node_id)?;

        let mut module_substates = BTreeMap::new();
        let mut component_substates = BTreeMap::new();
        for ((node_module_id, offset), substate) in node.substates {
            match node_module_id {
                NodeModuleId::SELF => component_substates.insert(offset, substate),
                _ => module_substates.insert((node_module_id, offset), substate),
            };
        }

        let mut module_init = BTreeMap::new();

        let type_info = module_substates
            .remove(&(
                NodeModuleId::TypeInfo,
                SubstateOffset::TypeInfo(TypeInfoOffset::TypeInfo),
            ))
            .unwrap();
        let mut type_info_substate: TypeInfoSubstate = type_info.into();
        type_info_substate.global = true;
        module_init.insert(
            NodeModuleId::TypeInfo,
            RENodeModuleInit::TypeInfo(type_info_substate),
        );

        // TODO: Check node type matches modules provided

        for (module_id, init) in modules {
            match module_id {
                NodeModuleId::SELF
                | NodeModuleId::TypeInfo
                | NodeModuleId::PackageRoyalty
                | NodeModuleId::FunctionAccessRules => {
                    return Err(RuntimeError::SystemError(SystemError::InvalidModule))
                }
                NodeModuleId::AccessRules | NodeModuleId::AccessRules1 => {
                    let access_rules: Own = scrypto_decode(&init).map_err(|e| {
                        RuntimeError::SystemError(SystemError::InvalidAccessRules(e))
                    })?;

                    let object_id = access_rules.id();
                    let node_id = RENodeId::Object(object_id);
                    let (package_address, blueprint) = self.get_object_type_info(node_id)?;
                    if !matches!(
                        (package_address, blueprint.as_str()),
                        (ACCESS_RULES_PACKAGE, ACCESS_RULES_BLUEPRINT)
                    ) {
                        return Err(RuntimeError::SystemError(SystemError::InvalidModuleType {
                            expected_package: ACCESS_RULES_PACKAGE,
                            expected_blueprint: ACCOUNT_BLUEPRINT.to_string(),
                            actual_package: package_address,
                            actual_blueprint: blueprint,
                        }));
                    }

                    let mut node = self.kernel_drop_node(RENodeId::Object(object_id))?;

                    let access_rules = node
                        .substates
                        .remove(&(
                            NodeModuleId::SELF,
                            SubstateOffset::AccessRules(AccessRulesOffset::AccessRules),
                        ))
                        .unwrap();
                    let access_rules: MethodAccessRulesSubstate = access_rules.into();

                    module_init
                        .insert(module_id, RENodeModuleInit::MethodAccessRules(access_rules));
                }
                NodeModuleId::Metadata => {
                    let metadata: Own = scrypto_decode(&init)
                        .map_err(|e| RuntimeError::SystemError(SystemError::InvalidMetadata(e)))?;

                    let object_id = metadata.id();
                    let node_id = RENodeId::Object(object_id);
                    let (package_address, blueprint) = self.get_object_type_info(node_id)?;
                    if !matches!(
                        (package_address, blueprint.as_str()),
                        (METADATA_PACKAGE, METADATA_BLUEPRINT)
                    ) {
                        return Err(RuntimeError::SystemError(SystemError::InvalidModuleType {
                            expected_package: METADATA_PACKAGE,
                            expected_blueprint: METADATA_BLUEPRINT.to_string(),
                            actual_package: package_address,
                            actual_blueprint: blueprint,
                        }));
                    }

                    let mut node = self.kernel_drop_node(node_id)?;

                    let metadata = node
                        .substates
                        .remove(&(
                            NodeModuleId::SELF,
                            SubstateOffset::Metadata(MetadataOffset::Metadata),
                        ))
                        .unwrap();
                    let metadata: MetadataSubstate = metadata.into();

                    module_init
                        .insert(NodeModuleId::Metadata, RENodeModuleInit::Metadata(metadata));
                }
                NodeModuleId::ComponentRoyalty => {
                    let royalty: Own = scrypto_decode(&init).map_err(|e| {
                        RuntimeError::SystemError(SystemError::InvalidRoyaltyConfig(e))
                    })?;

                    let object_id = royalty.id();
                    let node_id = RENodeId::Object(object_id);
                    let (package_address, blueprint) = self.get_object_type_info(node_id)?;
                    if !matches!(
                        (package_address, blueprint.as_str()),
                        (ROYALTY_PACKAGE, COMPONENT_ROYALTY_BLUEPRINT)
                    ) {
                        return Err(RuntimeError::SystemError(SystemError::InvalidModuleType {
                            expected_package: ROYALTY_PACKAGE,
                            expected_blueprint: COMPONENT_ROYALTY_BLUEPRINT.to_string(),
                            actual_package: package_address,
                            actual_blueprint: blueprint,
                        }));
                    }

                    let mut node = self.kernel_drop_node(node_id)?;

                    let config = node
                        .substates
                        .remove(&(
                            NodeModuleId::SELF,
                            SubstateOffset::Royalty(RoyaltyOffset::RoyaltyConfig),
                        ))
                        .unwrap();
                    let config: ComponentRoyaltyConfigSubstate = config.into();
                    let accumulator = node
                        .substates
                        .remove(&(
                            NodeModuleId::SELF,
                            SubstateOffset::Royalty(RoyaltyOffset::RoyaltyAccumulator),
                        ))
                        .unwrap();
                    let accumulator: ComponentRoyaltyAccumulatorSubstate = accumulator.into();

                    module_init.insert(
                        NodeModuleId::ComponentRoyalty,
                        RENodeModuleInit::ComponentRoyalty(config, accumulator),
                    );
                }
            }
        }

        self.kernel_create_node(
            address.into(),
            RENodeInit::GlobalObject(component_substates),
            module_init,
        )?;

        Ok(address.into())
    }

    fn call_method(
        &mut self,
        receiver: RENodeId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.call_module_method(receiver, NodeModuleId::SELF, method_name, args)
    }

    fn call_module_method(
        &mut self,
        receiver: RENodeId,
        node_module_id: NodeModuleId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeError> {
        let invocation = MethodInvocation {
            identifier: MethodIdentifier(receiver, node_module_id, method_name.to_string()),
            args,
        };

        self.kernel_invoke(invocation)
            .map(|v| scrypto_encode(&v).expect("Failed to encode scrypto fn return"))
    }

    fn get_object_type_info(
        &mut self,
        node_id: RENodeId,
    ) -> Result<(PackageAddress, String), RuntimeError> {
        TypeInfoBlueprint::get_type(node_id, self)
    }

    fn new_key_value_store(&mut self) -> Result<KeyValueStoreId, RuntimeError> {
        let node_id = self.kernel_allocate_node_id(RENodeType::KeyValueStore)?;

        self.kernel_create_node(node_id, RENodeInit::KeyValueStore, btreemap!())?;

        Ok(node_id.into())
    }
}

impl<'g, 's, W> ClientUnsafeApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn consume_cost_units(
        &mut self,
        units: u32,
        reason: ClientCostingReason,
    ) -> Result<(), RuntimeError> {
        KernelModuleMixer::on_consume_cost_units(self, units, reason)
    }

    fn credit_cost_units(
        &mut self,
        vault_id: ObjectId,
        locked_fee: LiquidFungibleResource,
        contingent: bool,
    ) -> Result<LiquidFungibleResource, RuntimeError> {
        KernelModuleMixer::on_credit_cost_units(self, vault_id, locked_fee, contingent)
    }

    fn update_instruction_index(&mut self, new_index: usize) -> Result<(), RuntimeError> {
        KernelModuleMixer::on_update_instruction_index(self, new_index)
    }

    fn update_wasm_memory_usage(&mut self, size: usize) -> Result<(), RuntimeError> {
        KernelModuleMixer::on_update_wasm_memory_usage(self, size)
    }
}

impl<'g, 's, W> ClientEventApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn emit_event<T: ScryptoEncode + abi::LegacyDescribe>(
        &mut self,
        event: T,
    ) -> Result<(), RuntimeError> {
        EventStoreNativePackage::emit_event(event, self)
    }

    fn emit_raw_event(
        &mut self,
        schema_hash: Hash,
        event_data: Vec<u8>,
    ) -> Result<(), RuntimeError> {
        EventStoreNativePackage::emit_raw_event(schema_hash, event_data, self)
    }
}

impl<'g, 's, W> ClientLoggerApi<RuntimeError> for Kernel<'g, 's, W>
where
    W: WasmEngine,
{
    fn log_message(&mut self, level: Level, message: String) -> Result<(), RuntimeError> {
        LoggerNativePackage::log_message(level, message, self)
    }
}

impl<'g, 's, W> ClientApi<RuntimeError> for Kernel<'g, 's, W> where W: WasmEngine {}
