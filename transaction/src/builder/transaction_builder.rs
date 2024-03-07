use crate::model::*;
use crate::signing::Signer;

pub struct TransactionBuilder {
    manifest: Option<TransactionManifestV1>,
    header: Option<TransactionHeaderV1>,
    message: Option<MessageV1>,
    intent_signatures: Vec<SignatureWithPublicKeyV1>,
    notary_signature: Option<SignatureV1>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            manifest: None,
            header: None,
            message: None,
            intent_signatures: vec![],
            notary_signature: None,
        }
    }

    pub fn manifest(mut self, manifest: TransactionManifestV1) -> Self {
        self.manifest = Some(manifest);
        self
    }

    pub fn header(mut self, header: TransactionHeaderV1) -> Self {
        self.header = Some(header);
        self
    }

    pub fn message(mut self, message: MessageV1) -> Self {
        self.message = Some(message);
        self
    }

    pub fn sign<S: Signer>(mut self, signer: &S) -> Self {
        let intent = self.transaction_intent();
        let prepared = intent.prepare().expect("Intent could be prepared");
        self.intent_signatures
            .push(signer.sign_with_public_key(&prepared.intent_hash()));
        self
    }

    pub fn multi_sign<S: Signer>(mut self, signers: &[&S]) -> Self {
        let intent = self.transaction_intent();
        let prepared = intent.prepare().expect("Intent could be prepared");
        for signer in signers {
            self.intent_signatures
                .push(signer.sign_with_public_key(&prepared.intent_hash()));
        }
        self
    }

    pub fn signer_signatures(mut self, sigs: Vec<SignatureWithPublicKeyV1>) -> Self {
        self.intent_signatures.extend(sigs);
        self
    }

    pub fn notarize<S: Signer>(mut self, signer: &S) -> Self {
        let signed_intent = self.signed_transaction_intent();
        let prepared = signed_intent
            .prepare()
            .expect("Signed intent could be prepared");
        self.notary_signature = Some(
            signer
                .sign_with_public_key(&prepared.signed_intent_hash())
                .signature(),
        );
        self
    }

    pub fn notary_signature(mut self, signature: SignatureV1) -> Self {
        self.notary_signature = Some(signature);
        self
    }

    pub fn build(&self) -> NotarizedTransactionV1 {
        NotarizedTransactionV1 {
            signed_intent: self.signed_transaction_intent(),
            notary_signature: NotarySignatureV1(
                self.notary_signature.clone().expect("Not notarized"),
            ),
        }
    }

    pub fn transaction_intent(&self) -> IntentV1 {
        let (instructions, blobs) = self
            .manifest
            .clone()
            .expect("Manifest not specified")
            .for_intent();
        IntentV1 {
            header: self.header.clone().expect("Header not specified"),
            instructions,
            blobs,
            message: self.message.clone().unwrap_or(MessageV1::None),
        }
    }

    pub fn signed_transaction_intent(&self) -> SignedIntentV1 {
        let intent = self.transaction_intent();
        SignedIntentV1 {
            intent,
            intent_signatures: IntentSignaturesV1 {
                signatures: self
                    .intent_signatures
                    .clone()
                    .into_iter()
                    .map(|sig| IntentSignatureV1(sig))
                    .collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;
    use std::num::ParseIntError;

    use radix_engine_common::crypto::{Ed25519PrivateKey, Secp256k1Signature};
    use radix_engine_common::types::{EntityType, Epoch, NodeId};
    use radix_engine_interface::crypto::PublicKey;
    use radix_engine_interface::network::NetworkDefinition;
    use radix_engine_common::prelude::AddressBech32Decoder;
    use radix_engine_common::prelude::XRD;
    use radix_engine_common::prelude::Ed25519PublicKey;
    use scrypto::types::ComponentAddress;
    use utils::rust::collections::indexmap::Equivalent;
    use std::str::FromStr;
    use radix_engine_common::prelude::AddressBech32Encoder;
    use utils::ContextualDisplay;
    use radix_engine_common::prelude::hash;

    use super::*;
    use crate::builder::*;
    use crate::internal_prelude::Secp256k1PrivateKey;

    fn create_address_from_string(input: &str) -> Option<ComponentAddress> {
        // Now turn this into an Radix address
        let address = ComponentAddress::try_from_bech32(&AddressBech32Decoder::new(&NetworkDefinition::mainnet()), input);
        address
    }

    #[test]
    fn notary_as_signatory() {
        let private_key = Secp256k1PrivateKey::from_u64(1).unwrap();

        let transaction = TransactionBuilder::new()
            .header(TransactionHeaderV1 {
                network_id: NetworkDefinition::simulator().id,
                start_epoch_inclusive: Epoch::zero(),
                end_epoch_exclusive: Epoch::of(100),
                nonce: 5,
                notary_public_key: private_key.public_key().into(),
                notary_is_signatory: true,
                tip_percentage: 5,
            })
            .manifest(ManifestBuilder::new().drop_auth_zone_proofs().build())
            .notarize(&private_key)
            .build();

        let prepared = transaction.prepare().unwrap();
        assert_eq!(
            prepared
                .signed_intent
                .intent
                .header
                .inner
                .notary_is_signatory,
            true
        );
    }

    fn create_transaction_to_notarize(
        network: NetworkDefinition,
        current_epoch: u64,
        valid_for_approx_mins: u64,
        manifest: TransactionManifestV1,
        public_key: PublicKey,
    ) -> (SignedIntentV1, SignedIntentHash) {
            let epoch_duration = (valid_for_approx_mins / 5) + 1;
            let signed_intent = TransactionBuilder::new()
                .header(TransactionHeaderV1 {
                    network_id: network.id,
                    start_epoch_inclusive: Epoch::of(current_epoch),
                    end_epoch_exclusive: Epoch::of(current_epoch + epoch_duration),
                    nonce: 0,
                    notary_public_key: public_key,
                    notary_is_signatory: true,
                    tip_percentage: 0,
                })
                .manifest(manifest)
                .signed_transaction_intent();
    
        let signed_intent_hash = signed_intent.prepare().unwrap().signed_intent_hash();
        (signed_intent, signed_intent_hash)
    }
    
    fn create_simple_transfer_manifest(
        source: ComponentAddress,
        target: ComponentAddress,
        amount: u64,
        fee: u32) -> TransactionManifestV1
    {
        // Create a temporary resource to store the XRD
        let manifest = ManifestBuilder::new()
        .lock_fee(source, fee)
        .withdraw_from_account(source, XRD, amount)
        .withdraw_from_account(source, XRD, amount)
        .take_from_worktop(XRD, amount, "bucket1")
        .try_deposit_or_abort(target, None, "bucket1")
        .build();
        manifest
    }

    fn sign_with_card(bytes_to_sign: SignedIntentHash) -> Secp256k1Signature {
        // Sign and return the signature
        let private_key = Secp256k1PrivateKey::from_u64(1).unwrap();
        let sig = private_key.sign(&bytes_to_sign);
        sig
    }

    fn combine_and_build_transaction(signed_intent: SignedIntentV1, signature_from_card: SignatureV1) -> Vec<u8> {
        let notarized_transaction = NotarizedTransactionV1 {
                signed_intent: signed_intent,
                notary_signature: NotarySignatureV1(signature_from_card),
            };
        let payload = notarized_transaction.to_raw().unwrap();
        payload.0
    }

    #[test]
    fn unsigned_tx_raw() {
        let private_key = Secp256k1PrivateKey::from_u64(1).unwrap();
        let source = "account_rdx128v3gk2z8wq4dppe59sseqhg852zzn6cqe6ctqnc0pelg0gm6euua2";
        let target = "account_rdx128v3gk2z8wq4dppe59sseqhg852zzn6cqe6ctqnc0pelg0gm6euua2";
        let amount = 100;
        let fee = 10;

        let source_address = create_address_from_string(source);
        let target_address = create_address_from_string(target);

        if source_address.is_some() && target_address.is_some() {
            let (signed_intent, hash) = create_transaction_to_notarize(NetworkDefinition::mainnet(),
                                                    1000, 20,
                                                    create_simple_transfer_manifest(source_address.unwrap(), target_address.unwrap(), amount, fee),
                                                    private_key.public_key().into());
    
            let signature_from_card = sign_with_card(hash);
            let transaction_payload_to_submit = combine_and_build_transaction(signed_intent, SignatureV1::from(signature_from_card));
            println!("TX Payload: {:?}\n", transaction_payload_to_submit);
        } else {
            println!("Unable to create address for {} or {}\n", source, target);
        }
    }

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    fn to_mainnet_address(address: &ComponentAddress) -> String {
        let mainnet = NetworkDefinition::mainnet();
        let address_encoder = AddressBech32Encoder::new(&mainnet);
        address.to_string(&address_encoder)
    }

    fn address_from_private_key_hex(private_key_hex: &str) -> String {
        let private_key_bytes = decode_hex(private_key_hex).unwrap();
        let private_key = Ed25519PrivateKey::from_bytes(&private_key_bytes).unwrap();
        let public_key = private_key.public_key();
        let address = ComponentAddress::virtual_account_from_public_key(&public_key);
        println!("{:?}", address);
        let hash = hash(public_key.to_vec());
        println!("Hash {:?}", hash);
        println!("Hash lower_bytes {:?}", hash.lower_bytes::<30>());
        let mut node_id: [u8; NodeId::LENGTH] = hash.lower_bytes();
        node_id[0] = EntityType::GlobalVirtualEd25519Account as u8;
        println!("node_id {:?}", node_id);
        let account_address = to_mainnet_address(&address);
        account_address
    }

    fn address_from_public_key_hex(public_key_hex: &str) -> String {
      // From a public key string
      let public_key = Ed25519PublicKey::from_str(public_key_hex);
      // Now turn this into an Radix address
      let address = ComponentAddress::virtual_account_from_public_key(&public_key.unwrap());
      let account_address= to_mainnet_address(&address);
      account_address
    }

    fn address_from_bec32_string(account_address: &str) {
        let target_address = ComponentAddress::try_from_bech32(&AddressBech32Decoder::new(&NetworkDefinition::mainnet()), account_address);
        if target_address.is_some() {
            // Convert to mainnet address and pring
            println!("Success converting to a ComponentAddress: {}", account_address);
        } else {
            println!("Failed converting to a ComponentAddress: {}", account_address);
        }
    }

    #[test]
    fn create_address_test() {
        //let private_key_hex = "afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5";
        //let public_key_hex = "4870d56d074c50e891506d78faa4fb69ca039cc5f131eb491e166b975880e867";

        // The private/public key info comes from a test in Trustwallet using a 24 word mnemonic generated
        // by the Radix iOS wallet
        // mnemonic is the following 24 words
        // knife catalog term act cinnamon umbrella
        // unknown unaware pluck often hill broccoli
        // casino pony sting lamp trick method
        // buffalo hat aisle float paper infant

        let private_key_hex = "56599d2a2945098767213e0f675f44de7e80216af4c77360ebd2f0864c6c1b65";
        let public_key_hex = "7ec219a00c9d6cd52ad95b1d663dcf8b0222d1dd1d34a52d25962de6fde215c8";
        // This account address is what comes from the Radix wallet using the same 24 work mnemonic
        let account_address = "account_rdx12xkxcwcn4enh4npy9pu9nrytryetq73rxqz4056j92tuhcvwp7e9la";

        let address_from_private_key = address_from_private_key_hex(private_key_hex);
        let address_from_public_key = address_from_public_key_hex(public_key_hex);
        assert_eq!(address_from_private_key, address_from_public_key);

        address_from_bec32_string(&address_from_public_key);

        assert_eq!(account_address, address_from_public_key);
    }
}
