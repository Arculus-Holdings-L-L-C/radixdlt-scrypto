use crate::engine::SystemApi;
use crate::wasm::*;
use sbor::*;
use scrypto::abi::{Function, Method};
use scrypto::buffer::scrypto_decode;
use scrypto::prelude::PackageFunction;
use scrypto::rust::collections::HashMap;
use scrypto::rust::string::String;
use scrypto::rust::vec::Vec;
use scrypto::values::ScryptoValue;

/// A collection of blueprints, compiled and published as a single unit.
#[derive(Debug, Clone, TypeId, Encode, Decode)]
pub struct Package {
    code: Vec<u8>,
    blueprints: HashMap<String, (Type, Vec<Function>, Vec<Method>)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PackageError {
    InvalidRequestData(DecodeError),
    BlueprintNotFound,
    WasmValidationError(WasmValidationError),
    MethodNotFound(String),
}

impl Package {
    /// Validates and creates a package
    pub fn new(code: Vec<u8>) -> Result<Self, WasmValidationError> {
        let mut wasm_engine = WasmiEngine::new(NopScryptoRuntime {});
        wasm_engine.validate(&code)?;

        let module = wasm_engine.instantiate(&code);
        let exports: Vec<String> = module
            .function_exports()
            .into_iter()
            .filter(|e| e.ends_with("_abi") && e.len() > 4)
            .collect();

        let mut blueprints = HashMap::new();
        for method_name in exports {
            let rtn = module
                .invoke_export(&method_name, &[])
                .map_err(|_| WasmValidationError::UnableToExportBlueprintAbi)?;

            let abi: (Type, Vec<Function>, Vec<Method>) =
                scrypto_decode(&rtn.raw).map_err(|_| WasmValidationError::InvalidBlueprintAbi)?;

            if let Type::Struct { name, fields: _ } = &abi.0 {
                blueprints.insert(name.clone(), abi);
            } else {
                return Err(WasmValidationError::InvalidBlueprintAbi);
            }
        }

        Ok(Self { blueprints, code })
    }

    pub fn code(&self) -> &[u8] {
        &self.code
    }

    pub fn blueprint_abi(
        &self,
        blueprint_name: &str,
    ) -> Result<&(Type, Vec<Function>, Vec<Method>), PackageError> {
        self.blueprints
            .get(blueprint_name)
            .ok_or(PackageError::BlueprintNotFound)
    }

    pub fn contains_blueprint(&self, blueprint_name: &str) -> bool {
        self.blueprints.contains_key(blueprint_name)
    }

    pub fn load_blueprint_schema(&self, blueprint_name: &str) -> Result<&Type, PackageError> {
        self.blueprint_abi(blueprint_name).map(|v| &v.0)
    }

    pub fn static_main<S: SystemApi>(
        call_data: ScryptoValue,
        system_api: &mut S,
    ) -> Result<ScryptoValue, PackageError> {
        let function: PackageFunction =
            scrypto_decode(&call_data.raw).map_err(|e| PackageError::InvalidRequestData(e))?;
        match function {
            PackageFunction::Publish(bytes) => {
                let package = Package::new(bytes).map_err(PackageError::WasmValidationError)?;
                let package_address = system_api.create_package(package);
                Ok(ScryptoValue::from_value(&package_address))
            }
        }
    }
}
