use scrypto::engine::scrypto_env::*;
use scrypto::prelude::*;
use scrypto::radix_engine_interface::api::node_modules::auth::*;
use scrypto::radix_engine_interface::api::node_modules::metadata::*;
use scrypto::radix_engine_interface::api::node_modules::royalty::*;
use scrypto::radix_engine_interface::api::ClientObjectApi;
use scrypto::radix_engine_interface::api::ClientPackageApi;

#[blueprint]
mod component_module {
    use crate::{AccessRules, RoyaltyConfig};

    struct ComponentModule {}

    impl ComponentModule {
        pub fn globalize_with_mixed_up_modules() -> ComponentAddress {
            let component = ComponentModule {}.instantiate();

            let rtn = ScryptoEnv
                .call_function(
                    METADATA_PACKAGE,
                    METADATA_BLUEPRINT,
                    METADATA_CREATE_IDENT,
                    scrypto_encode(&MetadataCreateInput {}).unwrap(),
                )
                .unwrap();
            let metadata: Own = scrypto_decode(&rtn).unwrap();

            let rtn = ScryptoEnv
                .call_function(
                    ROYALTY_PACKAGE,
                    COMPONENT_ROYALTY_BLUEPRINT,
                    COMPONENT_ROYALTY_CREATE_IDENT,
                    scrypto_encode(&ComponentRoyaltyCreateInput {
                        royalty_config: RoyaltyConfig::default(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let royalty: Own = scrypto_decode(&rtn).unwrap();

            let rtn = ScryptoEnv
                .call_function(
                    ACCESS_RULES_PACKAGE,
                    ACCESS_RULES_BLUEPRINT,
                    ACCESS_RULES_CREATE_IDENT,
                    scrypto_encode(&AccessRulesCreateInput {
                        access_rules: AccessRules::new(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let access_rules: Own = scrypto_decode(&rtn).unwrap();

            let address = ScryptoEnv
                .globalize(
                    RENodeId::Object(component.component.0),
                    btreemap!(
                        NodeModuleId::AccessRules => scrypto_encode(&metadata).unwrap(),
                        NodeModuleId::Metadata => scrypto_encode(&royalty).unwrap(),
                        NodeModuleId::ComponentRoyalty => scrypto_encode(&access_rules).unwrap()
                    ),
                )
                .unwrap();

            address.into()
        }
    }
}
