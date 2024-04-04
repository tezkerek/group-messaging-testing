use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use openmls_test::credential::make_credential;
use openmls_test::key_service::KeyService;

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(8)).sample_size(10);
    targets = add_members_simultaneously, add_members_individually
}
criterion_main!(benches);

struct BenchConfig {
    provider: OpenMlsRustCrypto,
    ciphersuite: Ciphersuite,
    group_config: MlsGroupConfig,
    self_credential: CredentialWithKey,
    self_signer: SignatureKeyPair,
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

fn create_group(bench_config: &BenchConfig) -> MlsGroup {
    MlsGroup::new(
        &bench_config.provider,
        &bench_config.self_signer,
        &bench_config.group_config,
        bench_config.self_credential.clone(),
    )
    .expect("Failed to create group")
}

fn add_members_simultaneously(c: &mut Criterion) {
    let config = BenchConfig::default();

    let mut bench_group = c.benchmark_group("simultaneous");
    bench_group.sampling_mode(SamplingMode::Flat);
    for count in [1, 50, 100, 500, 1000] {
        bench_group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |bencher, &count| {
                let mut key_service = KeyService::new();
                key_service
                    .generate(&config.ciphersuite, &config.provider, count)
                    .expect("Failed to populate KeyService");

                bencher.iter(|| {
                    let mut group = create_group(&config);
                    let all_packages: Vec<KeyPackage> =
                        key_service.packages().values().cloned().collect();
                    group
                        .add_members(&config.provider, &config.self_signer, &all_packages)
                        .expect("Failed to add members");
                    group
                        .merge_pending_commit(&config.provider)
                        .expect("Failed to commit add");
                })
            },
        );
    }
    bench_group.finish();
}

fn add_members_individually(c: &mut Criterion) {
    let config = BenchConfig::default();

    let mut bench_group = c.benchmark_group("individual");
    bench_group.sampling_mode(SamplingMode::Flat);
    for count in [1, 50, 100] {
        bench_group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |bencher, &count| {
                let mut key_service = KeyService::new();
                key_service
                    .generate(&config.ciphersuite, &config.provider, count)
                    .expect("Failed to populate KeyService");

                bencher.iter(|| {
                    let mut group = create_group(&config);
                    let all_packages: Vec<KeyPackage> =
                        key_service.packages().values().cloned().collect();
                    for package in all_packages {
                        group
                            .add_members(&config.provider, &config.self_signer, &[package])
                            .expect("Failed to add members");
                        group
                            .merge_pending_commit(&config.provider)
                            .expect("Failed to commit add");
                    }
                });
            },
        );
    }
    bench_group.finish();
}
