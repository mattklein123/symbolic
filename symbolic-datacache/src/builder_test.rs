use std::io::{self, Write};

use goblin::mach::symbols;
use symbolic_debuginfo::macho::MachObject;
use symbolic_testutils::macho::{data_section, data_symbol_fixture};

use crate::tests::golden;
use crate::{BuildError, BuildLimits, DataCache, DataCacheBuilder, ReadLimits, Reason, State};

const UUID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const BASE: u64 = 0x1_0000_0000;

fn build(bytes: &[u8], limits: BuildLimits) -> DataCacheBuilder {
    DataCacheBuilder::from_macho(&MachObject::parse(bytes).unwrap(), [17; 32], limits).unwrap()
}

fn budget_source() -> Vec<u8> {
    data_symbol_fixture(
        BASE,
        &[data_section("__DATA", "__data", BASE, 16, 0)],
        &[
            ("_a", symbols::N_SECT, 1, BASE),
            ("_b", symbols::N_SECT, 1, BASE),
            ("_c", symbols::N_SECT, 1, BASE + 2),
            ("_ignored", symbols::N_UNDF, 0, 0),
        ],
        Some(UUID),
    )
}

#[test]
fn writer_matches_independent_golden_byte_for_byte() {
    let source = data_symbol_fixture(
        BASE,
        &[data_section("__DATA", "__data", BASE, 16, 0)],
        &[("_a", symbols::N_SECT, 1, BASE)],
        Some(UUID),
    );
    let built = build(&source, BuildLimits::default());
    assert_eq!(built.as_bytes(), golden());
}

#[test]
fn preserves_large_offsets_overlapping_sections_and_raw_aliases() {
    let offsets = [
        0,
        u32::MAX as u64,
        0x1_0000_0000,
        6_498_870_784,
        u64::MAX - 2,
    ];
    let sections: Vec<_> = offsets
        .iter()
        .map(|address| data_section("__DATA", "__data", *address, 2, 0))
        .collect();
    let entries: Vec<_> = offsets
        .iter()
        .enumerate()
        .map(|(index, address)| ("_same_raw_name", symbols::N_SECT, index as u8 + 1, *address))
        .collect();
    let source = data_symbol_fixture(0, &sections, &entries, Some(UUID));
    let built = build(&source, BuildLimits::default());
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    for offset in offsets {
        assert_eq!(cache.lookup_exact(offset).next().unwrap().address, offset);
        assert_eq!(
            cache.lookup_exact(offset + 1).len(),
            usize::from(offsets.contains(&(offset + 1)))
        );
    }
    let section = data_section("__DATA", "__data", BASE, 16, 0);
    let source = data_symbol_fixture(
        BASE,
        &[section, section],
        &[
            ("_alias", symbols::N_SECT, 2, BASE),
            ("_alias", symbols::N_SECT, 1, BASE),
        ],
        Some(UUID),
    );
    let built = build(&source, BuildLimits::default());
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    assert_eq!(
        cache
            .lookup_exact(0)
            .map(|symbol| symbol.section.macho_ordinal)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn canonical_order_is_independent_of_iteration_and_duplicates_keep_diagnostics() {
    let sections = [data_section("__DATA", "__data", BASE, 16, 0)];
    let entries = [
        ("_b", symbols::N_SECT, 1, BASE),
        ("_a", symbols::N_SECT, 1, BASE),
    ];
    let built = build(
        &data_symbol_fixture(BASE, &sections, &entries, Some(UUID)),
        BuildLimits::default(),
    );
    let reversed = build(
        &data_symbol_fixture(BASE, &sections, &[entries[1], entries[0]], Some(UUID)),
        BuildLimits::default(),
    );
    assert_eq!(built.as_bytes(), reversed.as_bytes());
    let duplicated = build(
        &data_symbol_fixture(
            BASE,
            &sections,
            &[entries[0], entries[1], entries[0]],
            Some(UUID),
        ),
        BuildLimits::default(),
    );
    assert_eq!(&built.as_bytes()[256..], &duplicated.as_bytes()[256..]);
    assert_eq!(duplicated.statistics().accepted_records, 3);
    assert_eq!(built.statistics().accepted_records, 2);
    assert_eq!(
        DataCache::parse(duplicated.as_bytes(), ReadLimits::default())
            .unwrap()
            .record_count(),
        2
    );
}

#[test]
fn each_build_budget_has_explicit_terminal_state_at_its_boundary() {
    let source = budget_source();
    let complete = build(&source, BuildLimits::default());
    type Setter = fn(&mut BuildLimits, u64);
    let limits: [(u64, Reason, Setter); 8] = [
        (4, Reason::RawSymbolLimit, |limits, value| {
            limits.raw_symbols = value
        }),
        (3, Reason::RecordLimit, |limits, value| {
            limits.records = value
        }),
        (2, Reason::AliasLimit, |limits, value| {
            limits.aliases = value
        }),
        (8, Reason::NameLengthLimit, |limits, value| {
            limits.name_length = value as usize
        }),
        (14, Reason::ExaminedNameBytesLimit, |limits, value| {
            limits.examined_name_bytes = value
        }),
        (18, Reason::StringPoolLimit, |limits, value| {
            limits.string_bytes = value
        }),
        (
            complete.as_bytes().len() as u64,
            Reason::FileSizeLimit,
            |limits, value| limits.file_bytes = value,
        ),
        (
            complete.accounted_storage(),
            Reason::BuilderMemoryLimit,
            |limits, value| limits.memory_bytes = value,
        ),
    ];
    for (boundary, reason, set) in limits {
        for value in [boundary - 1, boundary, boundary + 1] {
            let mut limits = BuildLimits::default();
            set(&mut limits, value);
            let built = build(&source, limits);
            let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
            if value < boundary {
                assert_eq!(built.reason(), reason);
                assert_eq!(cache.state(), State::Incomplete);
                assert_eq!(built.as_bytes().len(), 256);
                assert_eq!(cache.lookup_exact(0).len(), 0);
            } else {
                assert_eq!(cache.state(), State::Complete, "{reason:?}: {value}");
            }
            assert!(built.accounted_storage() <= limits.memory_bytes);
        }
    }
    for limits in [
        BuildLimits {
            records: 0,
            ..BuildLimits::default()
        },
        BuildLimits {
            aliases: 0,
            ..BuildLimits::default()
        },
        BuildLimits {
            raw_symbols: 0,
            ..BuildLimits::default()
        },
    ] {
        assert_eq!(build(&source, limits).state(), State::Incomplete);
    }
}

#[test]
fn empty_complete_and_failed_extraction_are_distinct() {
    let empty = data_symbol_fixture(BASE, &[], &[], Some(UUID));
    let complete = build(&empty, BuildLimits::default());
    assert_eq!(complete.as_bytes().len(), 256);
    assert_eq!(complete.state(), State::Complete);
    assert_eq!(
        DataCache::parse(complete.as_bytes(), ReadLimits::default())
            .unwrap()
            .record_count(),
        0
    );
    let mut corrupt = budget_source();
    let last = corrupt.len() - 2;
    corrupt[last] = 255;
    let incomplete = build(&corrupt, BuildLimits::default());
    assert_eq!(incomplete.reason(), Reason::SourceError);
    assert_eq!(incomplete.as_bytes().len(), 256);
    let mut unknown = empty.clone();
    unknown[4..8].copy_from_slice(&0u32.to_le_bytes());
    let unsupported = build(&unknown, BuildLimits::default());
    assert_eq!(unsupported.state(), State::Unsupported);
    assert_eq!(
        DataCache::parse(unsupported.as_bytes(), ReadLimits::default())
            .unwrap()
            .lookup_exact(0)
            .len(),
        0
    );
}

struct FailedWriter;

impl Write for FailedWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn identity_configuration_and_output_errors_are_not_empty_successes() {
    let source = data_symbol_fixture(BASE, &[], &[], None);
    let object = MachObject::parse(&source).unwrap();
    assert!(matches!(
        DataCacheBuilder::from_macho(&object, [17; 32], BuildLimits::default()),
        Err(BuildError::MissingIdentity)
    ));
    let source = budget_source();
    let object = MachObject::parse(&source).unwrap();
    for limits in [
        BuildLimits {
            file_bytes: 255,
            ..BuildLimits::default()
        },
        BuildLimits {
            memory_bytes: 255,
            ..BuildLimits::default()
        },
    ] {
        assert!(matches!(
            DataCacheBuilder::from_macho(&object, [17; 32], limits),
            Err(BuildError::InvalidLimits)
        ));
    }
    let built = build(&source, BuildLimits::default());
    assert!(matches!(
        built.serialize(FailedWriter),
        Err(BuildError::Io(_))
    ));
    let mut output = Vec::new();
    built.serialize(&mut output).unwrap();
    assert_eq!(output, built.as_bytes());
}
