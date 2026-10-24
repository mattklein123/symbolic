use std::fs;
use std::path::Path;

use proptest::prelude::*;
use symbolic_common::{Arch, ByteView};

use crate::tests::{golden, independent_cache, repair, set32, set64};
use crate::{DataCache, ObjectKind, ParseError, ReadLimits, Reason, State};

#[test]
fn reads_independent_v1_golden_and_borrows_names() {
    let bytes = golden();
    assert_eq!(bytes.len(), 342);
    assert_eq!(&bytes[8..16], &[1, 0, 0, 0, 0, 1, 0, 0]);
    let cache = DataCache::parse(&bytes, ReadLimits::default()).unwrap();
    assert_eq!(cache.identity().arch, Arch::Arm64e);
    assert_eq!(cache.identity().preferred_load_address, 0x1_0000_0000);
    assert_eq!(cache.identity().object_kind, ObjectKind::Debug);
    assert_eq!(cache.identity().source_digest, [17; 32]);
    assert_eq!(cache.state(), State::Complete);
    assert_eq!(cache.reason(), Reason::None);
    assert_eq!(cache.statistics().accepted_records, 1);
    let mut matches = cache.lookup_exact(0);
    assert_eq!(matches.len(), 1);
    let symbol = matches.next().unwrap();
    assert_eq!(symbol.name, "_a");
    assert_eq!(symbol.name.as_ptr(), bytes[340..].as_ptr());
    assert_eq!(symbol.section.segment_name, "__DATA");
    assert_eq!(symbol.section.name, "__data");
    assert_eq!(symbol.section.size, 16);
    assert_eq!(matches.next(), None);
    for miss in [1, 15, 16, u64::MAX] {
        assert_eq!(cache.lookup_exact(miss).len(), 0);
    }
}

#[test]
fn exact_full_width_lookup_preserves_all_aliases_and_gaps() {
    let addresses = [
        0,
        20,
        u32::MAX as u64,
        0x1_0000_0000,
        6_498_870_784,
        u64::MAX - 1,
    ];
    let bytes = independent_cache(&addresses, 3);
    let cache = DataCache::parse(&bytes, ReadLimits::default()).unwrap();
    for address in addresses {
        let matches: Vec<_> = cache.lookup_exact(address).collect();
        assert_eq!(
            matches.iter().map(|symbol| symbol.name).collect::<Vec<_>>(),
            ["_a", "_b", "_c"]
        );
        assert!(matches.iter().all(|symbol| symbol.address == address));
    }
    for address in [1, 19, 21, u32::MAX as u64 - 1, 6_498_870_785, u64::MAX] {
        assert_eq!(cache.lookup_exact(address).len(), 0);
    }
}

#[test]
fn binary_search_has_logarithmic_comparison_bound() {
    let addresses: Vec<_> = (0..10_000).map(|index| index * 2).collect();
    let bytes = independent_cache(&addresses, 3);
    let cache = DataCache::parse(&bytes, ReadLimits::default()).unwrap();
    for address in [0, 1, 5000, 10_001, 19_998, 20_000, u64::MAX] {
        assert!(cache.comparison_count(address) <= 14);
    }
    assert_eq!(cache.lookup_exact(5000).len(), 3);
}

#[test]
fn supports_unaligned_and_mapped_bytes_after_unlink() {
    let bytes = golden();
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&bytes);
    assert_eq!(
        DataCache::parse(&unaligned[1..], ReadLimits::default())
            .unwrap()
            .record_count(),
        1
    );
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.tmp");
    fs::create_dir_all(&scratch).unwrap();
    let directory = tempfile::tempdir_in(scratch).unwrap();
    let path = directory.path().join("mapped.datacache");
    fs::write(&path, &bytes).unwrap();
    let mapping = ByteView::open(&path).unwrap();
    let symbol = {
        let cache = DataCache::parse(&mapping, ReadLimits::default()).unwrap();
        fs::remove_file(&path).unwrap();
        cache.lookup_exact(0).next().unwrap()
    };
    assert_eq!(symbol.name, "_a");
    assert!(symbol.name.as_ptr() >= mapping.as_ptr());
    assert!(symbol.name.as_ptr() < mapping[mapping.len()..].as_ptr());
}

#[test]
fn rejects_header_enums_identity_counters_and_terminal_payloads() {
    for (offset, value) in [
        (8, 2),
        (12, 255),
        (48, u32::MAX),
        (52, 4),
        (56, 3),
        (60, 11),
        (56, 1),
        (56, 2),
        (60, 2),
        (216, 1),
    ] {
        let mut bytes = golden();
        set32(&mut bytes, offset, value);
        assert!(
            DataCache::parse(&bytes, ReadLimits::default()).is_err(),
            "offset {offset}"
        );
    }
    let mut bytes = golden();
    bytes[24..40].fill(0);
    assert_eq!(
        DataCache::parse(&bytes, ReadLimits::default()).unwrap_err(),
        ParseError::Identity
    );
    for (offset, value) in [(16, 0), (192, 0), (200, 0), (208, 0), (208, 2)] {
        let mut bytes = golden();
        set64(&mut bytes, offset, value);
        assert!(DataCache::parse(&bytes, ReadLimits::default()).is_err());
    }
    let mut bytes = golden();
    set32(&mut bytes, 56, 1);
    set32(&mut bytes, 60, 2);
    assert_eq!(
        DataCache::parse(&bytes, ReadLimits::default()).unwrap_err(),
        ParseError::Layout
    );
}

#[test]
fn rejects_corrupt_tables_even_with_correct_checksum() {
    for (offset, value) in [
        (128, 255),
        (128, 264),
        (128, u64::MAX),
        (136, u64::MAX),
        (144, 256),
        (152, 0),
        (160, 280),
        (176, 329),
        (184, 13),
        (288, u64::MAX),
    ] {
        let mut bytes = golden();
        set64(&mut bytes, offset, value);
        repair(&mut bytes);
        assert!(
            DataCache::parse(&bytes, ReadLimits::default()).is_err(),
            "u64 offset {offset}"
        );
    }
    for (offset, value) in [
        (264, 1),
        (268, 0),
        (268, 2),
        (272, 1),
        (276, u32::MAX),
        (280, 0),
        (284, 1),
        (304, 0),
        (304, 256),
        (316, u32::MAX),
        (324, 17),
    ] {
        let mut bytes = golden();
        set32(&mut bytes, offset, value);
        repair(&mut bytes);
        assert!(
            DataCache::parse(&bytes, ReadLimits::default()).is_err(),
            "u32 offset {offset}"
        );
    }
    for (offset, value) in [(328, 255), (340, 0)] {
        let mut bytes = golden();
        bytes[offset] = value;
        repair(&mut bytes);
        assert!(DataCache::parse(&bytes, ReadLimits::default()).is_err());
    }
    let mut bytes = golden();
    bytes[340] ^= 1;
    assert_eq!(
        DataCache::parse(&bytes, ReadLimits::default()).unwrap_err(),
        ParseError::Checksum
    );
    for length in 0..golden().len() {
        assert!(DataCache::parse(&golden()[..length], ReadLimits::default()).is_err());
    }
    let mut bytes = golden();
    bytes.push(0);
    assert!(DataCache::parse(&bytes, ReadLimits::default()).is_err());
}

#[test]
fn rejects_unsorted_addresses_duplicate_aliases_and_invalid_membership() {
    let bytes = independent_cache(&[0, 2], 2);
    for (offset, value) in [(272, 0), (272, u64::MAX), (360, 2)] {
        let mut changed = bytes.clone();
        set64(&mut changed, offset, value);
        repair(&mut changed);
        assert!(
            DataCache::parse(&changed, ReadLimits::default()).is_err(),
            "u64 offset {offset}"
        );
    }
    for (offset, value) in [(308, 12), (280, 1), (284, 0)] {
        let mut changed = bytes.clone();
        set32(&mut changed, offset, value);
        repair(&mut changed);
        assert!(
            DataCache::parse(&changed, ReadLimits::default()).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn enforces_each_read_limit_at_its_boundary() {
    let bytes = independent_cache(&[0, 2], 2);
    type Setter = fn(&mut ReadLimits, u64);
    let limits: [(u64, Setter); 8] = [
        (bytes.len() as u64, |limits, value| {
            limits.file_bytes = value
        }),
        (2, |limits, value| limits.addresses = value),
        (4, |limits, value| limits.records = value),
        (1, |limits, value| limits.sections = value),
        (16, |limits, value| limits.string_bytes = value),
        (2, |limits, value| limits.aliases = value),
        (2, |limits, value| limits.name_length = value),
        (8, |limits, value| limits.referenced_name_bytes = value),
    ];
    for (boundary, set) in limits {
        for value in [boundary - 1, boundary, boundary + 1] {
            let mut limits = ReadLimits::default();
            set(&mut limits, value);
            assert_eq!(DataCache::parse(&bytes, limits).is_ok(), value >= boundary);
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = DataCache::parse(&bytes, ReadLimits::default());
    }

    #[test]
    fn mutated_golden_never_panics(changes in prop::collection::vec((0usize..342, any::<u8>()), 0..20), length in 0usize..343) {
        let mut bytes = golden();
        for (offset, value) in changes { bytes[offset] = value; }
        repair(&mut bytes);
        bytes.truncate(length);
        if let Ok(cache) = DataCache::parse(&bytes, ReadLimits::default()) {
            for address in [0, 1, u64::MAX] { let _ = cache.lookup_exact(address).collect::<Vec<_>>(); }
        }
    }
}

#[test]
fn complete_empty_cache_cannot_claim_accepted_records() {
    let mut bytes = golden();
    bytes.truncate(256);
    set64(&mut bytes, 16, 256);
    for index in 0..4 {
        set64(&mut bytes, 128 + index * 16, 256);
        set64(&mut bytes, 136 + index * 16, 0);
    }
    repair(&mut bytes);
    assert_eq!(
        DataCache::parse(&bytes, ReadLimits::default()).unwrap_err(),
        ParseError::Identity
    );
}
