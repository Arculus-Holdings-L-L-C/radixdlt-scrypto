use crate::types::*;

#[derive(Debug, Clone, TypeId, Encode, Decode, PartialEq, Eq)]
pub struct ComponentStateSubstate {
    pub raw: Vec<u8>,
}

impl ComponentStateSubstate {
    pub fn new(raw: Vec<u8>) -> Self {
        ComponentStateSubstate { raw }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[scrypto(TypeId, Encode, Decode)]
pub struct ComponentInfoSubstate {
    pub package_address: PackageAddress,
    pub blueprint_name: String,
}

impl ComponentInfoSubstate {
    pub fn new(package_address: PackageAddress, blueprint_name: String) -> Self {
        Self {
            package_address,
            blueprint_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[scrypto(TypeId, Encode, Decode)]
pub struct ComponentRoyaltyConfigSubstate {
    pub royalty_config: RoyaltyConfig,
}
