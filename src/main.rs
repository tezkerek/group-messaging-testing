use anyhow::{bail, Result};
use credential::{create_keypackage, make_credential};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_test::{
    key_service::KeyService,
    mls::{create_group_with_members, BenchConfig},
};

mod credential;
mod key_service;

static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

fn join_from_welcome(
    provider: &OpenMlsRustCrypto,
    welcome_out: &MlsMessageOut,
    group_config: &MlsGroupConfig,
    ratchet_tree_in: RatchetTreeIn,
) -> Result<MlsGroup> {
    let ser_welcome = welcome_out.tls_serialize_detached()?;
    let welcome_in = MlsMessageIn::tls_deserialize(&mut ser_welcome.as_slice())?;

    if let MlsMessageInBody::Welcome(welcome) = welcome_in.extract() {
        let group =
            MlsGroup::new_from_welcome(provider, group_config, welcome, Some(ratchet_tree_in))?;
        Ok(group)
    } else {
        bail!("Not a welcome message");
    }
}

fn main() -> Result<()> {
    let config = BenchConfig::default();
    for count in [2, 100, 1024] {
        let mut key_service = KeyService::new();
        key_service
            .generate(&config.ciphersuite, &config.provider, count)
            .expect("Failed to populate KeyService");

        let mut mls_group = create_group_with_members(&config, &key_service);

        fn quick_keypackage(
            ciphersuite: &Ciphersuite,
            provider: &impl OpenMlsCryptoProvider,
            identity: String,
        ) -> KeyPackage {
            let (new_credential, new_signer) =
                make_credential(ciphersuite, provider, identity.clone()).unwrap();
            let key_package =
                create_keypackage(ciphersuite.clone(), provider, new_credential, &new_signer)
                    .unwrap();
            key_package
        }
        let new_package = quick_keypackage(&config.ciphersuite, &config.provider, "Alice".into());
        let (remove_out, welcome, _) = mls_group
            .add_members(&config.provider, &config.self_signer, &[new_package])
            .expect("Failed to add members");

        let byte_count = remove_out.tls_serialized_len();

        println!(
            "Group size {}: {}, {} bytes",
            count,
            byte_count,
            welcome.tls_serialized_len()
        );
    }

    Ok(())
}
