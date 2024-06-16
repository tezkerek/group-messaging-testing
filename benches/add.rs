use std::time::Duration;

use anyhow::Result;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use openmls::prelude::*;

use openmls_test::credential::{create_keypackage, make_credential};
use openmls_test::key_service::KeyService;
use openmls_test::mls::{create_group, create_group_with_members, BenchConfig};
use openmls_test::ratchet::RatchetGroup;

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(1)).sample_size(10);
    targets = add_member_to_existing_group
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

fn add_member_to_existing_group(c: &mut Criterion) {
    let config = BenchConfig::default();

    let mut bench_group = c.benchmark_group("add_one");
    bench_group
        .measurement_time(Duration::from_secs(1))
        .sample_size(10)
        .sampling_mode(SamplingMode::Flat);
    for count in [2, 100, 1024] {
        bench_group.bench_with_input(
            BenchmarkId::new("TreeKEM", count),
            &count,
            |bencher, &count| {
                bencher.iter_batched(
                    || {
                        let mut key_service = KeyService::new();
                        key_service
                            .generate(&config.ciphersuite, &config.provider, count)
                            .expect("Failed to populate KeyService");

                        let mut mls_group = create_group_with_members(&config, &key_service);
                        let new_package =
                            quick_keypackage(&config.ciphersuite, &config.provider, "Alice".into())
                                .expect("Failed to create KeyPackage");
                        (mls_group, new_package)
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
        bench_group.bench_function(BenchmarkId::new("Pairwise Ratchet", count), |bencher| {
            bencher.iter_batched(
                || RatchetGroup::with_generated_members(count),
                |mut ratchet_group| {
                    ratchet_group.add_member();
                    let add_instruction = [1u8; 512];
                    ratchet_group.encrypt_message(&add_instruction);
                },
                BatchSize::LargeInput,
            );
        });
        bench_group.bench_function(BenchmarkId::new("Optimized Ratchet", count), |bencher| {
            bencher.iter_batched(
                || RatchetGroup::with_generated_members(count),
                |mut ratchet_group| {
                    ratchet_group.add_member();
                    let add_instruction = [1u8; 512];
                    ratchet_group.encrypt_message_efficiently(&add_instruction);
                },
                BatchSize::LargeInput,
            );
        });
    }
    bench_group.finish();
}
