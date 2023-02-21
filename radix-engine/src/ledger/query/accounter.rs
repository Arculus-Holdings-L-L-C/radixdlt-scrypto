use crate::ledger::{
    QueryableSubstateStore, ReadableSubstateStore, StateTreeTraverser, StateTreeTraverserError,
    StateTreeVisitor,
};
use crate::types::hash_map::Entry;
use crate::types::HashMap;
use radix_engine_interface::api::types::{RENodeId, ResourceAddress, VaultId};
use radix_engine_interface::blueprints::resource::LiquidResource;
use radix_engine_interface::math::Decimal;

pub struct ResourceAccounter<'s, S: ReadableSubstateStore + QueryableSubstateStore> {
    substate_store: &'s S,
    accounting: Accounting,
}

impl<'s, S: ReadableSubstateStore + QueryableSubstateStore> ResourceAccounter<'s, S> {
    pub fn new(substate_store: &'s S) -> Self {
        ResourceAccounter {
            substate_store,
            accounting: Accounting::new(),
        }
    }

    pub fn add_resources(&mut self, node_id: RENodeId) -> Result<(), StateTreeTraverserError> {
        let mut state_tree_visitor =
            StateTreeTraverser::new(self.substate_store, &mut self.accounting, 100);
        state_tree_visitor.traverse_all_descendents(None, node_id)
    }

    pub fn into_map(self) -> HashMap<ResourceAddress, Decimal> {
        self.accounting.balances
    }
}

struct Accounting {
    balances: HashMap<ResourceAddress, Decimal>,
}

impl Accounting {
    pub fn new() -> Self {
        Accounting {
            balances: HashMap::new(),
        }
    }

    pub fn add_liquid_resource(&mut self, resource: &LiquidResource) {
        match self.balances.entry(resource.resource_address()) {
            Entry::Occupied(mut e) => {
                let new_amount = resource.amount() + *e.get();
                e.insert(new_amount);
            }
            Entry::Vacant(e) => {
                e.insert(resource.amount());
            }
        }
    }
}

impl StateTreeVisitor for Accounting {
    fn visit_vault(&mut self, _parent_id: VaultId, vault: &LiquidResource) {
        self.add_liquid_resource(vault);
    }
}
