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
    targets = remove_member
}
criterion_main!(benches);

fn remove_member(c: &mut Criterion) {
    let config = BenchConfig::default();

    let mut bench_group = c.benchmark_group("remove");
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
                        mls_group
                    },
                    |mut group| {
                        group
                            .remove_members(
                                &config.provider,
                                &config.self_signer,
                                &[LeafNodeIndex::new(1)],
                            )
                            .expect("Failed to remove member");
                        group
                            .merge_pending_commit(&config.provider)
                            .expect("Failed to commit the remove");
                    },
                    BatchSize::LargeInput,
                );
            },
        );
        bench_group.bench_function(BenchmarkId::new("Pairwise Ratchet", count), |bencher| {
            bencher.iter_batched(
                || RatchetGroup::with_generated_members(count),
                |mut ratchet_group| {
                    ratchet_group.remove_member();
                    let remove_instruction = [1u8; 512];
                    ratchet_group.encrypt_message(&remove_instruction);
                },
                BatchSize::LargeInput,
            );
        });
        bench_group.bench_function(BenchmarkId::new("Optimized Ratchet", count), |bencher| {
            bencher.iter_batched(
                || RatchetGroup::with_generated_members(count),
                |mut ratchet_group| {
                    ratchet_group.remove_member();
                    let remove_instruction = [1u8; 512];
                    ratchet_group.encrypt_message_efficiently(&remove_instruction);
                },
                BatchSize::LargeInput,
            );
        });
    }
    bench_group.finish();
}
