use std::time::Duration;

use anyhow::Result;
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main, SamplingMode};
use openmls::prelude::*;

use openmls_test::credential::{create_keypackage, make_credential};
use openmls_test::key_service::KeyService;
use openmls_test::mls::{BenchConfig, create_group};

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(8));
    targets = add_members_simultaneously, add_members_individually, add_member_to_existing_group
}
criterion_main!(benches);

fn quick_keypackage(
    ciphersuite: &Ciphersuite,
    provider: &impl OpenMlsCryptoProvider,
    identity: String,
) -> Result<KeyPackage> {
    let (new_credential, new_signer) = make_credential(ciphersuite, provider, identity.clone())?;
    let key_package =
        create_keypackage(ciphersuite.clone(), provider, new_credential, &new_signer)?;
    Ok(key_package)
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
                    group
                        .add_members(
                            &config.provider,
                            &config.self_signer,
                            &key_service.all_packages(),
                        )
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
                    for package in key_service.all_packages() {
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

fn add_member_to_existing_group(c: &mut Criterion) {
    let config = BenchConfig::default();

    let mut bench_group = c.benchmark_group("add_one");
    bench_group
        .measurement_time(Duration::from_secs(10))
        .sampling_mode(SamplingMode::Flat);
    for count in [10, 100, 1000] {
        bench_group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |bencher, &count| {
                let mut key_service = KeyService::new();
                key_service
                    .generate(&config.ciphersuite, &config.provider, count)
                    .expect("Failed to populate KeyService");

                let all_packages: Vec<KeyPackage> =
                    key_service.packages().values().cloned().collect();

                bencher.iter_batched(
                    || {
                        let mut group = create_group(&config);
                        group
                            .add_members(&config.provider, &config.self_signer, &all_packages)
                            .expect("Failed to add members");
                        group
                            .merge_pending_commit(&config.provider)
                            .expect("Failed to commit add");

                        let new_package =
                            quick_keypackage(&config.ciphersuite, &config.provider, "Alice".into())
                                .expect("Failed to create KeyPackage");

                        (group, new_package)
                    },
                    |(mut group, new_package)| {
                        group
                            .add_members(&config.provider, &config.self_signer, &[new_package])
                            .expect("Failed to add members");
                        group
                            .merge_pending_commit(&config.provider)
                            .expect("Failed to commit add");
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    bench_group.finish();
}
