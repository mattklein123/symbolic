use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use goblin::mach::symbols;
use sha2::{Digest, Sha256};
use symbolic_common::ByteView;
use symbolic_datacache::{BuildLimits, DataCache, DataCacheBuilder, ReadLimits, State};
use symbolic_debuginfo::macho::MachObject;
use symbolic_testutils::macho::{data_section, data_symbol_fixture};

fn benchmark(c: &mut Criterion) {
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.tmp");
    fs::create_dir_all(&scratch).unwrap();
    let directory = tempfile::tempdir_in(scratch).unwrap();
    let mut group = c.benchmark_group("datacache");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_secs(1));
    for count in [100usize, 10_000, 100_000] {
        let names: Vec<_> = (0..count).map(|index| format!("_row_{index:06}")).collect();
        let mut entries: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(index, name)| (name.as_str(), symbols::N_SECT, 1, index as u64 * 16))
            .collect();
        entries.extend([
            ("_alias_a", symbols::N_SECT, 1, 0),
            ("_alias_b", symbols::N_SECT, 1, 0),
        ]);
        let source = data_symbol_fixture(
            0,
            &[data_section("__DATA", "__data", 0, count as u64 * 16, 0)],
            &entries,
            Some([1; 16]),
        );
        let digest: [u8; 32] = Sha256::digest(&source).into();
        let object = MachObject::parse(&source).unwrap();
        let built = DataCacheBuilder::from_macho(&object, digest, BuildLimits::default()).unwrap();
        assert_eq!(built.state(), State::Complete);
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        eprintln!(
            "datacache: addresses={count}, records={}, bytes={}, accounted_builder_bytes={}",
            cache.record_count(),
            built.as_bytes().len(),
            built.accounted_storage()
        );
        group.bench_function(BenchmarkId::new("build", count), |bench| {
            bench.iter(|| {
                DataCacheBuilder::from_macho(black_box(&object), digest, BuildLimits::default())
                    .unwrap()
            })
        });
        group.bench_function(BenchmarkId::new("serialize", count), |bench| {
            bench.iter(|| {
                let mut output = Vec::with_capacity(built.as_bytes().len());
                built.serialize(&mut output).unwrap();
                black_box(output)
            })
        });
        group.bench_function(BenchmarkId::new("validate", count), |bench| {
            bench.iter(|| {
                DataCache::parse(black_box(built.as_bytes()), ReadLimits::default()).unwrap()
            })
        });
        let path = directory.path().join(format!("{count}.datacache"));
        fs::write(&path, built.as_bytes()).unwrap();
        group.bench_function(BenchmarkId::new("map_validate", count), |bench| {
            bench.iter(|| {
                let mapping = ByteView::open(&path).unwrap();
                let cache = DataCache::parse(&mapping, ReadLimits::default()).unwrap();
                black_box(cache.record_count())
            })
        });
        let hit = (count as u64 * 2 / 3) * 16;
        group.bench_function(BenchmarkId::new("warm_hit", count), |bench| {
            bench.iter(|| {
                black_box(
                    cache
                        .lookup_exact(black_box(hit))
                        .map(|symbol| symbol.name.len())
                        .sum::<usize>(),
                )
            })
        });
        group.bench_function(BenchmarkId::new("warm_miss", count), |bench| {
            bench.iter(|| black_box(cache.lookup_exact(black_box(1)).count()))
        });
        group.bench_function(BenchmarkId::new("warm_aliases", count), |bench| {
            bench.iter(|| {
                black_box(
                    cache
                        .lookup_exact(black_box(0))
                        .map(|symbol| symbol.name.len())
                        .sum::<usize>(),
                )
            })
        });
        let linear: Vec<_> = object.data_symbols().unwrap().map(Result::unwrap).collect();
        group.bench_function(BenchmarkId::new("linear_hit", count), |bench| {
            bench.iter(|| {
                let address = black_box(hit);
                black_box(
                    linear
                        .iter()
                        .filter(|symbol| symbol.address == address)
                        .count(),
                )
            })
        });
        group.bench_function(BenchmarkId::new("linear_miss", count), |bench| {
            bench.iter(|| {
                let address = black_box(1);
                black_box(
                    linear
                        .iter()
                        .filter(|symbol| symbol.address == address)
                        .count(),
                )
            })
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
