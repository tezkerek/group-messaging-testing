use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, SamplingMode};

use openmls_test::key_service::KeyService;
use openmls_test::mls::{BenchConfig, create_group_with_members};
use openmls_test::ratchet::RatchetGroup;

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(8));
    targets = encrypt_messages
}
criterion_main!(benches);

fn encrypt_messages(c: &mut Criterion) {
    let config = BenchConfig::default();
    let mut bench_group = c.benchmark_group("encrypt");
    bench_group.sampling_mode(SamplingMode::Flat);

    let message = [1u8; 1024];
    for count in [100, 1024, 10000, 50000] {
        let mut ratchet_group = RatchetGroup::with_generated_members(count);
        let mut key_service = KeyService::new();
        key_service
            .generate(&config.ciphersuite, &config.provider, count)
            .expect("Failed to populate KeyService");
        let mut mls_group = create_group_with_members(&config, &key_service.all_packages());

        bench_group.bench_with_input(
            BenchmarkId::new("Pairwise Ratchet", count),
            &count,
            |bencher, &_count| {
                bencher.iter(|| {
                    ratchet_group.encrypt_message(&message);
                });
            },
        );
        bench_group.bench_with_input(
            BenchmarkId::new("Optimized Ratchet", count),
            &count,
            |bencher, &_count| {
                bencher.iter(|| {
                    ratchet_group.encrypt_message_efficiently(&message);
                });
            },
        );
        bench_group.bench_with_input(
            BenchmarkId::new("TreeKEM", count),
            &count,
            |bencher, &_count| {
                bencher.iter(|| {
                    ratchet_group.encrypt_message_efficiently(&message);
                    mls_group
                        .create_message(&config.provider, &config.self_signer, &message)
                        .expect("Failed to create MLS message");
                });
            },
        );
    }
    bench_group.finish();
}
