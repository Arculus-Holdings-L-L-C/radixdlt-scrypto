use radix_engine::types::*;
use scrypto_unit::*;
use transaction::builder::ManifestBuilder;

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

const PACKAGE_ADDRESS_PLACE_HOLDER: [u8; NodeId::LENGTH] = [
    13, 144, 99, 24, 198, 49, 140, 100, 247, 152, 202, 204, 99, 24, 198, 49, 140, 247, 189, 241,
    172, 105, 67, 234, 38, 49, 140, 99, 24, 198,
];

// TODO: disallow this behavior once every package is forced to declare dependencies.
#[test]
fn test_call_package_address_undeclared() {
    // Arrange
    let mut test_runner = TestRunner::builder().build();
    let package_address1 = test_runner.compile_and_publish("./tests/blueprints/cross_package_call");

    let (mut code, mut schema) = Compile::compile("./tests/blueprints/cross_package_call");
    let place_holder: GlobalAddress =
        PackageAddress::new_or_panic(PACKAGE_ADDRESS_PLACE_HOLDER).into();
    for (_, blueprint) in &mut schema.blueprints {
        if blueprint.dependencies.contains(&place_holder) {
            blueprint.dependencies.remove(&place_holder);
            blueprint.dependencies.insert(package_address1.into());
        }
    }

    let start = find_subsequence(&code, &PACKAGE_ADDRESS_PLACE_HOLDER).unwrap();
    code[start..start + PACKAGE_ADDRESS_PLACE_HOLDER.len()]
        .copy_from_slice(package_address1.as_ref());
    let package_address2 = test_runner.publish_package(
        code,
        schema,
        BTreeMap::new(),
        BTreeMap::new(),
        AuthorityRules::new(),
    );

    let manifest = ManifestBuilder::new()
        .lock_fee(test_runner.faucet_component(), 10.into())
        .call_function(
            package_address2,
            "Sample",
            "call_external_package",
            manifest_args!(),
        )
        .build();
    let receipt = test_runner.execute_manifest(manifest, vec![]);

    // Assert
    receipt.expect_commit_success();
}
