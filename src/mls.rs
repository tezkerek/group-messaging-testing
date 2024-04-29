use openmls::credentials::CredentialWithKey;
use openmls::group::config::CryptoConfig;
use openmls::prelude::{Ciphersuite, KeyPackage, MlsGroup, MlsGroupConfig};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::credential::make_credential;

pub struct BenchConfig {
    pub provider: OpenMlsRustCrypto,
    pub ciphersuite: Ciphersuite,
    pub group_config: MlsGroupConfig,
    pub self_credential: CredentialWithKey,
    pub self_signer: SignatureKeyPair,
}

impl Default for BenchConfig {
    fn default() -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
        let provider = OpenMlsRustCrypto::default();
        let group_config = MlsGroupConfig::builder()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .use_ratchet_tree_extension(true)
            .build();
        let (self_credential, self_signer) =
            make_credential(&ciphersuite, &provider, "Alice".into()).unwrap();
        BenchConfig {
            provider,
            ciphersuite,
            group_config,
            self_credential,
            self_signer,
        }
    }
}

pub fn create_group(bench_config: &BenchConfig) -> MlsGroup {
    MlsGroup::new(
        &bench_config.provider,
        &bench_config.self_signer,
        &bench_config.group_config,
        bench_config.self_credential.clone(),
    )
    .expect("Failed to create group")
}

pub fn create_group_with_members(
    bench_config: &BenchConfig,
    key_packages: &[KeyPackage],
) -> MlsGroup {
    let mut group = create_group(bench_config);
    group
        .add_members(
            &bench_config.provider,
            &bench_config.self_signer,
            key_packages,
        )
        .expect("Failed to add members");
    group
}
