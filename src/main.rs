#![feature(test)]

extern crate test;

use anyhow::{bail, Result};
use credential::make_credential;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

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
    Ok(())
}

#[cfg(test)]
mod tests {
    use openmls_basic_credential::SignatureKeyPair;
    use test::Bencher;

    use self::key_service::KeyService;

    use super::*;

    struct BenchConfig {
        provider: OpenMlsRustCrypto,
        group_config: MlsGroupConfig,
        self_credential: CredentialWithKey,
        self_signer: SignatureKeyPair,
    }

    impl Default for BenchConfig {
        fn default() -> Self {
            let provider = OpenMlsRustCrypto::default();
            let group_config = MlsGroupConfig::builder()
                .crypto_config(CryptoConfig::with_default_version(CIPHERSUITE))
                .use_ratchet_tree_extension(true)
                .build();
            let (self_credential, self_signer) =
                make_credential(&CIPHERSUITE, &provider, "Alice".into()).unwrap();
            BenchConfig {
                provider,
                group_config,
                self_credential,
                self_signer,
            }
        }
    }

    fn create_group(bench_config: &BenchConfig) -> MlsGroup {
        MlsGroup::new(
            &bench_config.provider,
            &bench_config.self_signer,
            &bench_config.group_config,
            bench_config.self_credential.clone(),
        )
        .expect("Failed to create group")
    }

    #[bench]
    fn bench_add_members_simultaneously(b: &mut Bencher) {
        let config = BenchConfig::default();
        let mut key_service = KeyService::new();
        key_service
            .generate(&CIPHERSUITE, &config.provider, 10)
            .expect("Failed to populate KeyService");

        b.iter(|| {
            let mut group = create_group(&config);
            let all_packages: Vec<KeyPackage> = key_service.packages().values().cloned().collect();
            group
                .add_members(&config.provider, &config.self_signer, &all_packages)
                .expect("Failed to add members");
            group
                .merge_pending_commit(&config.provider)
                .expect("Failed to commit add");
        });
    }

    #[bench]
    fn bench_add_members_individually(b: &mut Bencher) {
        let config = BenchConfig::default();

        let mut key_service = KeyService::new();
        key_service
            .generate(&CIPHERSUITE, &config.provider, 10)
            .expect("Failed to populate KeyService");

        b.iter(|| {
            let mut group = create_group(&config);
            let all_packages: Vec<KeyPackage> = key_service.packages().values().cloned().collect();
            for package in all_packages {
                group
                    .add_members(&config.provider, &config.self_signer, &[package])
                    .expect("Failed to add members");
                group
                    .merge_pending_commit(&config.provider)
                    .expect("Failed to commit add");
            }
        });
    }
}
