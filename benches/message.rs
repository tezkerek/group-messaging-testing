use std::time::Duration;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, PlotConfiguration, SamplingMode,
};

use openmls_test::key_service::KeyService;
use openmls_test::mls::{create_bare_group_with_members, create_group_with_members, BenchConfig};
use openmls_test::ratchet::RatchetGroup;

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(1)).sample_size(10);
    targets = encrypt_messages, message_roundtrip_bare, message_roundtrip
}
criterion_main!(benches);

fn encrypt_messages(c: &mut Criterion) {
    let config = BenchConfig::default();
    let mut bench_group = c.benchmark_group("encrypt");
    bench_group
        .sampling_mode(SamplingMode::Flat)
        .plot_config(PlotConfiguration::default().summary_scale(criterion::AxisScale::Logarithmic));

    for msg_size in [1, 10, 100] {
        let message = vec![1u8; msg_size * 1024];
        for count in [2, 100, 1024] {
            let mut ratchet_group = RatchetGroup::with_generated_members(count);
            let mut key_service = KeyService::new();
            key_service
                .generate(&config.ciphersuite, &config.provider, count)
                .expect("Failed to populate KeyService");
            let mut mls_group = create_group_with_members(&config, &key_service);

            let scenario_name = format!("{}_{}kb", count, msg_size);

            bench_group.bench_function(BenchmarkId::new("TreeKEM", &scenario_name), |bencher| {
                bencher.iter(|| {
                    mls_group
                        .create_message(&config.provider, &config.self_signer, &message)
                        .expect("Failed to create MLS message");
                });
            });
            bench_group.bench_function(
                BenchmarkId::new("Pairwise Ratchet", &scenario_name),
                |bencher| {
                    bencher.iter(|| {
                        ratchet_group.encrypt_message(&message);
                    });
                },
            );
            bench_group.bench_function(
                BenchmarkId::new("Optimized Ratchet", &scenario_name),
                |bencher| {
                    bencher.iter(|| {
                        ratchet_group.encrypt_message_efficiently(&message);
                    });
                },
            );
        }
    }
    bench_group.finish();
}

fn message_roundtrip_bare(c: &mut Criterion) {
    let config = BenchConfig::default();
    let mut bench_group = c.benchmark_group("roundtrip_bare");
    bench_group.sampling_mode(SamplingMode::Flat);

    for msg_size in [1, 10, 100] {
        let message = vec![1u8; msg_size * 1024];
        for count in [2, 100, 1024] {
            let mut ratchet_group = RatchetGroup::with_generated_members(count);

            let mut key_service = KeyService::new();
            key_service
                .generate(&config.ciphersuite, &config.provider, count)
                .expect("Failed to populate KeyService");
            let mut mls_group = create_bare_group_with_members(&config, &key_service);

            bench_group.bench_with_input(
                BenchmarkId::new("TreeKEM", count),
                &count,
                |bencher, &_count| {
                    bencher.iter(|| {
                        for _ in 1..=10 {
                            mls_group
                                .create_message(&config.provider, &config.self_signer, &message)
                                .expect("Failed to create MLS message");
                        }
                        mls_group
                            .self_update(&config.provider, &config.self_signer)
                            .expect("Failed to update own leaf node");
                        mls_group
                            .merge_pending_commit(&config.provider)
                            .expect("Failed to merge pending commits");
                    });
                },
            );
            bench_group.bench_with_input(
                BenchmarkId::new("Pairwise Ratchet", count),
                &count,
                |bencher, &_count| {
                    bencher.iter(|| {
                        for _ in 1..10 {
                            ratchet_group.encrypt_message(&message);
                        }
                        let incoming_message = ratchet_group.encrypt_from_member(1, &message);
                        _ = ratchet_group.decrypt_message(
                            1,
                            &incoming_message.0,
                            &incoming_message.1,
                            &incoming_message.2,
                        );
                    });
                },
            );
            bench_group.bench_with_input(
                BenchmarkId::new("Optimized Ratchet", count),
                &count,
                |bencher, &_count| {
                    bencher.iter(|| {
                        for _ in 1..=10 {
                            ratchet_group.encrypt_message_efficiently(&message);
                        }
                        let incoming_message = ratchet_group.encrypt_from_member(1, &message);
                        _ = ratchet_group.decrypt_message(
                            1,
                            &incoming_message.0,
                            &incoming_message.1,
                            &incoming_message.2,
                        );
                    });
                },
            );
        }
    }
    bench_group.finish();
}

fn message_roundtrip(c: &mut Criterion) {
    let config = BenchConfig::default();
    let mut bench_group = c.benchmark_group("roundtrip_10kb");
    bench_group.sampling_mode(SamplingMode::Flat);

    let message = [1u8; 10 * 1024];
    for count in [2, 100, 1024] {
        let mut ratchet_group = RatchetGroup::with_generated_members(count);

        let mut key_service = KeyService::new();
        key_service
            .generate(&config.ciphersuite, &config.provider, count)
            .expect("Failed to populate KeyService");
        let mut mls_group = create_group_with_members(&config, &key_service);

        bench_group.bench_with_input(
            BenchmarkId::new("TreeKEM", count),
            &count,
            |bencher, &_count| {
                bencher.iter(|| {
                    for _ in 1..=10 {
                        mls_group
                            .create_message(&config.provider, &config.self_signer, &message)
                            .expect("Failed to create MLS message");
                    }
                    mls_group
                        .self_update(&config.provider, &config.self_signer)
                        .expect("Failed to update own leaf node");
                    mls_group
                        .merge_pending_commit(&config.provider)
                        .expect("Failed to merge pending commits");
                });
            },
        );
        bench_group.bench_with_input(
            BenchmarkId::new("Pairwise Ratchet", count),
            &count,
            |bencher, &_count| {
                bencher.iter(|| {
                    for _ in 1..=10 {
                        ratchet_group.encrypt_message(&message);
                    }
                    let incoming_message = ratchet_group.encrypt_from_member(1, &message);
                    _ = ratchet_group.decrypt_message(
                        1,
                        &incoming_message.0,
                        &incoming_message.1,
                        &incoming_message.2,
                    );
                });
            },
        );
        bench_group.bench_with_input(
            BenchmarkId::new("Optimized Ratchet", count),
            &count,
            |bencher, &_count| {
                bencher.iter(|| {
                    for _ in 1..=10 {
                        ratchet_group.encrypt_message_efficiently(&message);
                    }
                    let incoming_message = ratchet_group.encrypt_from_member(1, &message);
                    _ = ratchet_group.decrypt_message(
                        1,
                        &incoming_message.0,
                        &incoming_message.1,
                        &incoming_message.2,
                    );
                });
            },
        );
    }
    bench_group.finish();
}
