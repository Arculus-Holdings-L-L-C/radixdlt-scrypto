use crate::construct_address;
use crate::model::*;

// After changing Radix Engine ID allocation, you will most likely need to update the addresses below.
//
// To obtain the new addresses, uncomment the println code in `id_allocator.rs` and
// run `cd radix-engine && cargo test -- bootstrap_receipt_should_match_constants --nocapture`.
//
// We've arranged the addresses in the order they're created in the genesis transaction.

/// The address of the faucet package.
pub const FAUCET_PACKAGE: PackageAddress = construct_address!(
    EntityType::Package,
    141,
    155,
    15,
    11,
    75,
    56,
    26,
    144,
    11,
    25,
    176,
    220,
    194,
    134,
    211,
    7,
    178,
    76,
    145,
    105,
    44,
    106,
    6,
    99,
    122,
    49
);
pub const FAUCET_BLUEPRINT: &str = "Faucet";

/// The address of the account package.
pub const ACCOUNT_PACKAGE: PackageAddress = construct_address!(
    EntityType::Package,
    183,
    5,
    84,
    120,
    29,
    187,
    91,
    52,
    106,
    12,
    202,
    40,
    56,
    242,
    194,
    46,
    214,
    59,
    64,
    82,
    248,
    103,
    140,
    64,
    210,
    19
);
pub const ACCOUNT_BLUEPRINT: &str = "Account";

/// The ECDSA virtual resource address.
pub const ECDSA_SECP256K1_TOKEN: ResourceAddress = construct_address!(
    EntityType::Resource,
    197,
    145,
    49,
    208,
    59,
    205,
    57,
    14,
    91,
    255,
    113,
    67,
    162,
    242,
    190,
    254,
    113,
    134,
    95,
    83,
    154,
    232,
    216,
    228,
    190,
    35
);

/// The system token which allows access to system resources (e.g. setting epoch)
pub const SYSTEM_TOKEN: ResourceAddress = construct_address!(
    EntityType::Resource,
    199, 24, 137, 61, 178, 84, 252, 213, 183, 107, 209, 173, 144, 5, 46, 12, 223, 13, 133, 8, 176, 152, 95, 216, 120, 51
);

/// The XRD resource address.
pub const RADIX_TOKEN: ResourceAddress = construct_address!(
    EntityType::Resource,
    173, 230, 44, 236, 86, 88, 189, 135, 83, 22, 29, 41, 209, 111, 122, 254, 105, 9, 133, 235, 11, 172, 192, 226, 128, 64
);

/// The address of the faucet component, test network only.
pub const FAUCET_COMPONENT: ComponentAddress = construct_address!(
    EntityType::NormalComponent,
    51, 112, 129, 183, 184, 244, 163, 95, 218, 117, 244, 128, 134, 100, 153, 207, 215, 243, 188, 209, 242, 31, 200, 35, 100, 163
);

pub const CLOCK: SystemAddress = construct_address!(
    EntityType::Clock,
    210, 4, 203, 199, 253, 87, 86, 55, 225, 160, 209, 125, 34, 246, 206, 141, 224, 160, 236, 54, 219, 221, 233, 10, 33, 79
);

/// The ED25519 virtual resource address.
pub const EDDSA_ED25519_TOKEN: ResourceAddress = construct_address!(
    EntityType::Resource,
    116, 117, 173, 206, 105, 144, 92, 116, 248, 225, 130, 72, 94, 142, 60, 167, 52, 186, 5, 29, 146, 198, 120, 157, 206, 226
);

pub const PACKAGE_TOKEN: ResourceAddress = construct_address!(
    EntityType::Resource,
    241, 80, 14, 193, 40, 120, 1, 16, 50, 105, 249, 218, 195, 64, 201, 162, 23, 173, 172, 153, 29, 117, 113, 45, 245, 16
);

pub const EPOCH_MANAGER: SystemAddress = construct_address!(
    EntityType::EpochManager,
    51, 112, 129, 183, 184, 244, 163, 95, 218, 117, 244, 128, 134, 100, 153, 207, 215, 243, 188, 209, 242, 31, 200, 35, 100, 163
);
