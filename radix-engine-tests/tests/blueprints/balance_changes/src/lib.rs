use scrypto::prelude::*;

#[blueprint]
mod balance_changes_test {
    struct BalanceChangesTest {
        vault: Vault,
    }

    impl BalanceChangesTest {
        pub fn instantiate() -> Global<BalanceChangesTestComponent> {
            let mut local_component = Self {
                vault: Vault::new(RADIX_TOKEN),
            }
            .instantiate();

            let royalty = {
                let config = RoyaltyConfigBuilder::new()
                    .add_rule("put", 1)
                    .add_rule("boom", 1)
                    .default(0);
                Royalty::new(config)
            };

            let mut authority_rules = AuthorityRules::new();
            authority_rules.set_rule("owner", rule!(allow_all), rule!(allow_all));

            local_component.attach_royalty(royalty);
            local_component.globalize_with_modules(
                AccessRules::new(MethodAuthorities::new(), authority_rules),
            )
        }

        pub fn put(&mut self, bucket: Bucket) {
            self.vault.put(bucket);
        }

        pub fn boom(&mut self, bucket: Bucket) {
            self.vault.put(bucket);
            panic!("Boom!")
        }
    }
}
