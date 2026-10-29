//! Synthetic Mach-O fixtures exercise raw-symbol and rooted-ABI extraction independently of system
//! binaries. File offsets intentionally differ from virtual addresses so pointer translation is part
//! of each fixture's contract, not an accidental consequence of identity-mapped test data.

use std::io::{self, Write};

use goblin::mach::symbols;
use symbolic_debuginfo::macho::MachObject;
use symbolic_testutils::macho::{data_section, data_symbol_fixture};

use crate::format::{read_u32, write_u32, write_u64};
use crate::tests::golden;
use crate::{
    AddressSpace, BuildError, BuildLimits, DataCache, DataCacheBuilder, ReadLimits, Reason,
    RecordKind, State,
};

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
fn instruction_symbols_have_exact_typed_records_without_undefined_synthetic_names() {
    let source = data_symbol_fixture(
        BASE,
        &[data_section("__TEXT", "__text", BASE, 16, 0x8000_0400)],
        &[
            ("_function", symbols::N_SECT, 1, BASE + 4),
            ("_synthetic_method", symbols::N_UNDF, 0, BASE + 8),
        ],
        Some(UUID),
    );
    let built = build(&source, BuildLimits::default());
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    assert_eq!(
        u32::from_le_bytes(built.as_bytes()[8..12].try_into().unwrap()),
        2
    );
    let record = cache.lookup_exact(4).next().unwrap();
    assert_eq!(record.name, "_function");
    assert_eq!(record.kind, RecordKind::Function);
    assert_eq!(cache.lookup_exact(5).len(), 0);
    assert_eq!(cache.lookup_exact(8).len(), 0);
    assert_eq!(cache.record_count(), 1);
}

/// Stripped class graph: classlist -> class -> class_ro_t, plus isa -> metaclass -> metaclass_ro_t.
/// VM offsets 0x1000/0x2000/0x3000/0x4000 map to file offsets 0x1000/0x1100/0x1200/0x1300.
fn runtime_source() -> Vec<u8> {
    let mut sections = [
        data_section("__DATA", "__objc_classlist", BASE + 0x1000, 8, 0),
        data_section("__DATA", "__objc_data", BASE + 0x2000, 0x80, 0),
        data_section("__DATA_CONST", "__objc_const", BASE + 0x3000, 0x100, 0),
        data_section("__TEXT", "__cstring", BASE + 0x4000, 0x40, 0),
    ];
    for (index, section) in sections.iter_mut().enumerate() {
        section.offset = 0x1000 + index as u32 * 0x100;
    }
    let mut source = data_symbol_fixture(BASE, &sections, &[], Some(UUID));
    source.resize(0x1400, 0);
    // Root points to the class. Class and metaclass are 0x40 apart; each data-bits slot is at +32.
    // Metaclass isa points to itself, proving extraction does not recursively chase isa forever.
    write_u64(&mut source, 0x1000, BASE + 0x2000);
    write_u64(&mut source, 0x1100, BASE + 0x2040);
    write_u64(&mut source, 0x1120, BASE + 0x3000);
    write_u64(&mut source, 0x1140, BASE + 0x2040);
    write_u64(&mut source, 0x1160, BASE + 0x3080);
    // class_ro_t start/size/name occupy +4/+8/+24; metaclass data at +0x80 also sets RO_META=1.
    write_u32(&mut source, 0x1204, 8);
    write_u32(&mut source, 0x1208, 16);
    write_u64(&mut source, 0x1218, BASE + 0x4000);
    write_u32(&mut source, 0x1280, 1);
    write_u32(&mut source, 0x1284, 40);
    write_u32(&mut source, 0x1288, 40);
    write_u64(&mut source, 0x1298, BASE + 0x4000);
    source[0x1300..0x1306].copy_from_slice(b"Probe\0");
    source
}

#[test]
fn stripped_runtime_metadata_preserves_structure_and_field_kinds() {
    let source = runtime_source();
    let built = build(&source, BuildLimits::default());
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    for (address, kind, name) in [
        (0x2000, RecordKind::ClassObject, "Probe"),
        (0x2040, RecordKind::MetaclassObject, "Probe"),
        (0x3000, RecordKind::ClassData, "Probe"),
        (0x3080, RecordKind::MetaclassData, "Probe"),
        (0x3018, RecordKind::ClassDataField, "Probe / name"),
    ] {
        let record = cache.lookup_exact(address).next().unwrap();
        assert_eq!((record.kind, record.name), (kind, name));
    }
    assert_eq!(cache.lookup_exact(0x3001).len(), 0);
    assert_eq!(cache.statistics().declared_symbols, 0);
    assert_eq!(cache.record_count(), 32);
}

#[test]
fn chained_rebases_recover_the_same_stripped_metadata() {
    let mut source = runtime_source();
    // mach_header_64 is 32 bytes; ncmds/sizeofcmds are at +16/+20. Append a 16-byte
    // LC_DYLD_CHAINED_FIXUPS command (0x80000034) pointing at the blob appended at file +0x1400.
    let commands_end = 32 + read_u32(&source, 20) as usize;
    let command_count = read_u32(&source, 16);
    write_u32(&mut source, 16, command_count + 1);
    write_u32(&mut source, 20, commands_end as u32 - 32 + 16);
    write_u32(&mut source, commands_end, 0x8000_0034);
    write_u32(&mut source, commands_end + 4, 16);
    write_u32(&mut source, commands_end + 8, 0x1400);
    write_u32(&mut source, commands_end + 12, 124);
    // The fixture starts with an empty base segment, then one 72-byte segment command plus one
    // 80-byte section header per section. Supply fileoff/filesize at segment +40/+48 for chain reads.
    for (index, size) in [8, 0x80, 0x100, 0x40].into_iter().enumerate() {
        let segment = 32 + 72 + index * 152;
        write_u64(&mut source, segment + 40, 0x1000 + index as u64 * 0x100);
        write_u64(&mut source, segment + 48, size);
    }
    // Blob = 28-byte fixup header + 24-byte starts table (five segments) + three 24-byte page tables.
    // The empty base segment and string segment have no chains. Each populated segment has one
    // 4-KiB page, PTR_64_OFFSET=6, and a VM offset relative to BASE rather than a file offset.
    let mut fixups = vec![0; 124];
    write_u32(&mut fixups, 4, 28);
    write_u32(&mut fixups, 28, 5);
    for index in 0..3 {
        write_u32(&mut fixups, 36 + index * 4, 24 + index as u32 * 24);
        let info = 52 + index * 24;
        write_u32(&mut fixups, info, 24);
        fixups[info + 4..info + 6].copy_from_slice(&4096u16.to_le_bytes());
        fixups[info + 6..info + 8].copy_from_slice(&6u16.to_le_bytes());
        write_u64(&mut fixups, info + 8, 0x1000 + index as u64 * 0x1000);
        fixups[info + 20..info + 22].copy_from_slice(&1u16.to_le_bytes());
    }
    // The const segment's first pointer is its class-name slot at +24, not the start of class_ro_t.
    fixups[122..124].copy_from_slice(&24u16.to_le_bytes());
    source.extend_from_slice(&fixups);
    // Replace plain addresses with PTR_64_OFFSET targets and next-link units of four bytes.
    // Thus next=8 advances 32 bytes between class slots, and next=32 spans the two RO name slots.
    for (offset, target, next) in [
        (0x1000, 0x2000, 0),
        (0x1100, 0x2040, 8),
        (0x1120, 0x3000, 8),
        (0x1140, 0x2040, 8),
        (0x1160, 0x3080, 0),
        (0x1218, 0x4000, 32),
        (0x1298, 0x4000, 0),
    ] {
        write_u64(&mut source, offset, target | next << 51);
    }
    let built = build(&source, BuildLimits::default());
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    assert_eq!(cache.lookup_exact(0x3000).next().unwrap().name, "Probe");
    assert_eq!(
        cache.lookup_exact(0x2040).next().unwrap().kind,
        RecordKind::MetaclassObject
    );
    assert_eq!(cache.record_count(), 32);
    // First page table begins at blob +52; pointer_format is its u16 at +6. An unknown format
    // skips metadata rather than reading the packed words as ordinary absolute pointers.
    source[0x1400 + 58..0x1400 + 60].copy_from_slice(&99u16.to_le_bytes());
    let unsupported = build(&source, BuildLimits::default());
    assert_eq!(
        DataCache::parse(unsupported.as_bytes(), ReadLimits::default())
            .unwrap()
            .record_count(),
        0
    );
}

struct ConstantContext;

impl AddressSpace for ConstantContext {
    fn read(&self, address: u64, size: usize) -> Option<&[u8]> {
        b"External\0"
            .get(usize::try_from(address.checked_sub(BASE + 0x9000)?).ok()?..)
            .and_then(|bytes| bytes.get(..size))
    }

    fn symbol_name(&self, address: u64) -> Option<&str> {
        match address {
            0x99 => Some("_OBJC_CLASS_$___NSCFConstantString"),
            0x98 => Some("_OBJC_CLASS_$_NSConstantIntegerNumber"),
            0x97 => Some("_OBJC_CLASS_$_NSConstantDictionary"),
            _ => None,
        }
    }

    fn objc_selector_base(&self) -> Option<u64> {
        Some(BASE + 0x4000 - 0x8000_0000)
    }
}

#[test]
fn pooled_metadata_names_are_materialized_without_a_lookup_time_context() {
    let mut source = runtime_source();
    write_u64(&mut source, 0x1218, BASE + 0x9000);
    write_u64(&mut source, 0x1298, BASE + 0x9000);
    let object = MachObject::parse(&source).unwrap();
    let built = DataCacheBuilder::from_macho_with_context(
        &object,
        [17; 32],
        BuildLimits::default(),
        Some(&ConstantContext),
    )
    .unwrap();
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    assert_eq!(cache.lookup_exact(0x3000).next().unwrap().name, "External");
}

#[test]
fn constant_strings_require_known_runtime_class_flags_and_valid_encoding() {
    for (isa, flags, characters, expected) in [
        (0x99, 0x7c8, b"Probe".as_slice(), Some("\"Probe\"")),
        (0x98, 0x7c8, b"Probe".as_slice(), None),
        (0x99, 0x1234, b"Probe".as_slice(), None),
        (
            0x99,
            0x7d0,
            b"P\0r\0o\0b\0e\0".as_slice(),
            Some("\"Probe\""),
        ),
        (0x99, 0x7d0, b"\0\xd8".as_slice(), None),
        (0x99, 0x7c8, b"\xff".as_slice(), None),
    ] {
        let mut source = runtime_source();
        // Reuse the first section as a single __cfstring object: its section header begins at 176.
        // Segment vmsize at 136 and section size at 216 must both cover the new 32-byte root.
        source[176..192].fill(0);
        source[176..186].copy_from_slice(b"__cfstring");
        write_u64(&mut source, 136, 32);
        write_u64(&mut source, 216, 32);
        write_u64(&mut source, 0x1000, isa);
        write_u64(&mut source, 0x1008, flags);
        write_u64(&mut source, 0x1010, BASE + 0x4000);
        write_u64(
            &mut source,
            0x1018,
            (characters.len() / if flags == 0x7d0 { 2 } else { 1 }) as u64,
        );
        source[0x1300..0x1300 + characters.len()].copy_from_slice(characters);
        let object = MachObject::parse(&source).unwrap();
        let built = DataCacheBuilder::from_macho_with_context(
            &object,
            [17; 32],
            BuildLimits::default(),
            Some(&ConstantContext),
        )
        .unwrap();
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        assert_eq!(cache.record_count(), if expected.is_some() { 4 } else { 0 });
        if let Some(expected) = expected {
            let record = cache.lookup_exact(0x1000).next().unwrap();
            assert_eq!(record.kind, RecordKind::ConstantString);
            assert_eq!(record.name, expected);
            assert_eq!(cache.lookup_exact(0x1001).len(), 0);
        }
    }
}

#[test]
fn mixed_cfnetwork_constants_require_complete_validated_objects() {
    let mut source = runtime_source();
    source[176..192].fill(0);
    source[176..190].copy_from_slice(b"__cfstring_CFN");
    write_u64(&mut source, 136, 88);
    write_u64(&mut source, 216, 88);
    source[0x1000..0x1058].fill(0);
    for offset in [8, 48] {
        write_u64(&mut source, 0x1000 + offset, 0x99);
        write_u64(&mut source, 0x1008 + offset, 0x7c8);
        write_u64(&mut source, 0x1010 + offset, BASE + 0x4000);
        write_u64(&mut source, 0x1018 + offset, 5);
    }
    write_u64(&mut source, 0x1050, 0x99);
    let object = MachObject::parse(&source).unwrap();
    let built = DataCacheBuilder::from_macho_with_context(
        &object,
        [17; 32],
        BuildLimits::default(),
        Some(&ConstantContext),
    )
    .unwrap();
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    for address in [0x1008, 0x1030] {
        let record = cache.lookup_exact(address).next().unwrap();
        assert_eq!(record.kind, RecordKind::ConstantString);
        assert_eq!(record.name, "\"Probe\"");
    }
    assert_eq!(cache.lookup_exact(0x1050).len(), 0);
    assert_eq!(cache.record_count(), 8);
}

#[test]
fn constant_objects_require_exact_classes_and_supported_abis() {
    for (section, size, isa, expected) in [
        ("__objc_intobj", 24, 0x98, Some(RecordKind::ConstantInteger)),
        ("__objc_intobj", 24, 0x99, None),
        (
            "__objc_dictobj",
            40,
            0x97,
            Some(RecordKind::ConstantDictionary),
        ),
        ("__objc_dictobj", 40, 0x99, None),
    ] {
        let mut source = runtime_source();
        source[176..192].fill(0);
        source[176..176 + section.len()].copy_from_slice(section.as_bytes());
        write_u64(&mut source, 136, size);
        write_u64(&mut source, 216, size);
        source[0x1000..0x1040].fill(0);
        write_u64(&mut source, 0x1000, isa);
        if section == "__objc_intobj" {
            write_u64(&mut source, 0x1008, BASE + 0x4000);
            write_u64(&mut source, 0x1010, 11);
            source[0x1300..0x1302].copy_from_slice(b"q\0");
        } else {
            write_u64(&mut source, 0x1010, 2);
            write_u64(&mut source, 0x1018, BASE + 0x2000);
            write_u64(&mut source, 0x1020, BASE + 0x2040);
        }
        let object = MachObject::parse(&source).unwrap();
        let built = DataCacheBuilder::from_macho_with_context(
            &object,
            [17; 32],
            BuildLimits::default(),
            Some(&ConstantContext),
        )
        .unwrap();
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        assert_eq!(
            cache.lookup_exact(0x1000).next().map(|record| record.kind),
            expected
        );
        assert_eq!(cache.lookup_exact(0x1001).len(), 0);
        if expected == Some(RecordKind::ConstantInteger) {
            assert_eq!(cache.lookup_exact(0x1000).next().unwrap().name, "11");
        }
        if expected == Some(RecordKind::ConstantDictionary) {
            assert_eq!(
                cache.lookup_exact(0x1010).next().unwrap().name,
                "2 entries / count"
            );
        }
    }
}

#[test]
fn rooted_methods_decode_absolute_relative_and_tagged_lists() {
    for (relative, tagged) in [(false, false), (true, false), (true, true)] {
        let mut source = runtime_source();
        write_u32(&mut source, 632 + 64, 0x8000_0400);
        write_u64(
            &mut source,
            0x1220,
            BASE + if tagged { 0x3061 } else { 0x3048 },
        );
        write_u32(&mut source, 0x1248, if relative { 0xc000_000c } else { 24 });
        write_u32(&mut source, 0x124c, 1);
        if relative {
            write_u32(&mut source, 0x1250, 0x8000_0000);
            write_u32(&mut source, 0x1258, 0x4020 - 0x3058);
        } else {
            write_u64(&mut source, 0x1250, BASE + 0x4000);
            write_u64(&mut source, 0x1260, BASE + 0x4020);
        }
        if tagged {
            write_u32(&mut source, 0x1260, 8);
            write_u32(&mut source, 0x1264, 1);
            write_u64(&mut source, 0x1268, (-32i64 as u64) << 16);
        }
        let object = MachObject::parse(&source).unwrap();
        let built = DataCacheBuilder::from_macho_with_context(
            &object,
            [17; 32],
            BuildLimits::default(),
            Some(&ConstantContext),
        )
        .unwrap();
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        let implementation = cache.lookup_exact(0x4020).next().unwrap();
        assert_eq!(implementation.kind, RecordKind::MethodImplementation);
        assert_eq!(implementation.name, "-[Probe Probe]");
        let field = cache
            .lookup_exact(0x3050 + if relative { 8 } else { 16 })
            .next()
            .unwrap();
        assert_eq!(field.kind, RecordKind::MethodEntry);
        assert_eq!(field.name, "-[Probe Probe] / implementation");
        assert_eq!(cache.lookup_exact(0x4021).len(), 0);
    }
}

#[test]
fn selector_pool_membership_alignment_and_provenance_are_explicit() {
    struct Context(Vec<u8>);
    impl AddressSpace for Context {
        fn read(&self, address: u64, size: usize) -> Option<&[u8]> {
            if address >= BASE + 0x10000 {
                let start = usize::try_from(address - BASE - 0x10000).ok()?;
                return self.0.get(start..start.checked_add(size)?);
            }
            let start = usize::try_from(address.checked_sub(BASE + 0x1080)?).ok()?;
            b"verified\0nearby\0notMember\0".get(start..start.checked_add(size)?)
        }
        fn symbol_name(&self, _: u64) -> Option<&str> {
            None
        }
        fn objc_selector_table(&self) -> Option<u64> {
            Some(BASE + 0x10000)
        }
    }
    let mut source = runtime_source();
    source[112..128].fill(0);
    source[112..121].copy_from_slice(b"__OBJC_RO");
    write_u64(&mut source, 136, 0x1000);
    source[176..192].fill(0);
    source[176..184].copy_from_slice(b"__unused");
    let mut table = vec![0; 1080];
    write_u32(&mut table, 4, 4);
    write_u32(&mut table, 8, 2);
    write_u32(&mut table, 1061, (-0xef80i32) as u32);
    write_u32(&mut table, 1065, (-0xef7fi32) as u32);
    let mut context = Context(table);
    let object = MachObject::parse(&source).unwrap();
    let built = DataCacheBuilder::from_macho_with_context(
        &object,
        [17; 32],
        BuildLimits::default(),
        Some(&context),
    )
    .unwrap();
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    let record = cache.lookup_exact(0x1080).next().unwrap();
    assert_eq!(record.kind, RecordKind::Selector);
    assert_eq!(record.name, "verified");
    assert_eq!(record.section.macho_ordinal, 0);
    assert_eq!(record.section.segment_name, "__OBJC_RO");
    assert_eq!(cache.lookup_exact(0x1081).len(), 0);
    assert_eq!(cache.lookup_exact(0x1090).len(), 0);
    assert_eq!(cache.record_count(), 1);

    let mut bytes = built.as_bytes().to_vec();
    let records = crate::format::read_u64(&bytes, 144) as usize;
    write_u32(&mut bytes, records + 12, RecordKind::ClassData as u32);
    let checksum = crate::format::digest(&bytes[256..]);
    bytes[96..128].copy_from_slice(&checksum);
    assert_eq!(
        DataCache::parse(&bytes, ReadLimits::default()).unwrap_err(),
        crate::ParseError::Reference
    );
    write_u32(&mut context.0, 8, 3);
    let rejected = DataCacheBuilder::from_macho_with_context(
        &object,
        [17; 32],
        BuildLimits::default(),
        Some(&context),
    )
    .unwrap();
    assert_eq!(
        DataCache::parse(rejected.as_bytes(), ReadLimits::default())
            .unwrap()
            .record_count(),
        0
    );
    write_u32(&mut context.0, 8, 2);
    for (limits, reason) in [
        (
            BuildLimits {
                raw_symbols: 1,
                ..BuildLimits::default()
            },
            Reason::RawSymbolLimit,
        ),
        (
            BuildLimits {
                records: 0,
                ..BuildLimits::default()
            },
            Reason::RecordLimit,
        ),
    ] {
        let rejected =
            DataCacheBuilder::from_macho_with_context(&object, [17; 32], limits, Some(&context))
                .unwrap();
        let cache = DataCache::parse(rejected.as_bytes(), ReadLimits::default()).unwrap();
        assert_eq!(cache.state(), State::Incomplete);
        assert_eq!(cache.reason(), reason);
        assert_eq!(cache.record_count(), 0);
    }
}

#[test]
fn malformed_runtime_roots_and_metadata_budgets_are_not_guessed() {
    for (offset, value) in [
        (0x1000, BASE + 0x2001),
        (0x1120, u64::MAX),
        (0x1218, u64::MAX),
    ] {
        let mut source = runtime_source();
        write_u64(&mut source, offset, value);
        let built = build(&source, BuildLimits::default());
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        assert_eq!(cache.record_count(), 0);
    }
    let built = build(
        &runtime_source(),
        BuildLimits {
            records: 2,
            ..BuildLimits::default()
        },
    );
    assert_eq!(built.state(), State::Incomplete);
    assert_eq!(built.reason(), Reason::RecordLimit);
    assert_eq!(built.as_bytes().len(), 256);

    let built = build(
        &runtime_source(),
        BuildLimits {
            examined_name_bytes: 5,
            ..BuildLimits::default()
        },
    );
    assert_eq!(built.reason(), Reason::ExaminedNameBytesLimit);

    let mut source = runtime_source();
    // Mark __objc_data as S_ZEROFILL via section_64.flags at +64. Segment/section headers still
    // exist, but bytes at the apparent file offset are not valid on-disk metadata to recover.
    write_u32(&mut source, 32 + 72 + 152 + 72 + 64, 1);
    assert_eq!(
        DataCache::parse(
            build(&source, BuildLimits::default()).as_bytes(),
            ReadLimits::default()
        )
        .unwrap()
        .record_count(),
        0
    );
}

#[test]
fn swift_type_table_recovers_qualified_descriptor_names_without_symbols() {
    let mut sections = [
        data_section("__TEXT", "__swift5_types", BASE + 0x1000, 4, 0),
        data_section("__TEXT", "__const", BASE + 0x2000, 0x80, 0),
        data_section("__TEXT", "__cstring", BASE + 0x3000, 0x40, 0),
    ];
    for (index, section) in sections.iter_mut().enumerate() {
        section.offset = 0x1000 + index as u32 * 0x100;
    }
    let mut source = data_symbol_fixture(BASE, &sections, &[], Some(UUID));
    source.resize(0x1300, 0);
    // Root VM +0x1000 points relatively to struct +0x2000. Its parent (+4) targets module +0x2040;
    // struct/module name fields (+8) point to strings at +0x3000/+0x3020. Zero module flags select
    // ContextDescriptorKind::Module; the struct's low-five-bit kind is 17.
    write_u32(&mut source, 0x1000, 0x1000);
    write_u32(&mut source, 0x1100, 17);
    write_u32(&mut source, 0x1104, 0x3c);
    write_u32(&mut source, 0x1108, 0xff8);
    write_u32(&mut source, 0x1148, 0xfd8);
    source[0x1200..0x1206].copy_from_slice(b"Probe\0");
    source[0x1220..0x1227].copy_from_slice(b"Module\0");
    let built = build(&source, BuildLimits::default());
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    let record = cache.lookup_exact(0x2000).next().unwrap();
    assert_eq!(record.kind, RecordKind::SwiftTypeDescriptor);
    assert_eq!(record.name, "Module.Probe");
    assert_eq!(cache.lookup_exact(0x2001).len(), 0);
    assert_eq!(
        cache.lookup_exact(0x2008).next().unwrap().name,
        "Module.Probe / name"
    );
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

fn append_load_command(source: &mut Vec<u8>, command: &[u8]) {
    let count = read_u32(source, 16);
    let size = read_u32(source, 20);
    let mut offset = 32;
    for _ in 0..count {
        if read_u32(source, offset) == 2 {
            let symbols = read_u32(source, offset + 8);
            let strings = read_u32(source, offset + 16);
            write_u32(source, offset + 8, symbols + command.len() as u32);
            write_u32(source, offset + 16, strings + command.len() as u32);
        }
        offset += read_u32(source, offset + 4) as usize;
    }
    let end = 32 + size as usize;
    source.splice(end..end, command.iter().copied());
    write_u32(source, 16, count + 1);
    write_u32(source, 20, size + command.len() as u32);
}

#[test]
fn selector_pool_and_all_255_macho_sections_round_trip_with_explicit_read_limits() {
    struct Context(Vec<u8>);
    impl AddressSpace for Context {
        fn read(&self, address: u64, size: usize) -> Option<&[u8]> {
            let (bytes, base) = if address >= BASE + 0x10000 {
                (self.0.as_slice(), BASE + 0x10000)
            } else {
                (b"verified\0".as_slice(), BASE + 0x1080)
            };
            let offset = usize::try_from(address.checked_sub(base)?).ok()?;
            bytes.get(offset..offset.checked_add(size)?)
        }

        fn symbol_name(&self, _: u64) -> Option<&str> {
            None
        }

        fn objc_selector_table(&self) -> Option<u64> {
            Some(BASE + 0x10000)
        }
    }
    let sections: Vec<_> = (0..255)
        .map(|index| data_section("__DATA", "__data", BASE + 0x100000 + index * 0x1000, 8, 0))
        .collect();
    let names: Vec<_> = (0..255).map(|index| format!("_record{index}")).collect();
    let symbols: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                name.as_str(),
                symbols::N_SECT,
                index as u8 + 1,
                sections[index].addr,
            )
        })
        .collect();
    let mut source = data_symbol_fixture(BASE, &sections, &symbols, Some(UUID));
    let mut pool = vec![0; 72];
    write_u32(&mut pool, 0, 0x19);
    write_u32(&mut pool, 4, 72);
    pool[8..17].copy_from_slice(b"__OBJC_RO");
    write_u64(&mut pool, 24, BASE + 0x1000);
    write_u64(&mut pool, 32, 0x100);
    append_load_command(&mut source, &pool);
    let mut table = vec![0; 1080];
    write_u32(&mut table, 4, 4);
    write_u32(&mut table, 8, 1);
    write_u32(&mut table, 1061, (-0xef80i32) as u32);
    let context = Context(table);
    let object = MachObject::parse(&source).unwrap();
    let built = DataCacheBuilder::from_macho_with_context(
        &object,
        [17; 32],
        BuildLimits::default(),
        Some(&context),
    )
    .unwrap();
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    assert_eq!(cache.state(), State::Complete);
    assert_eq!(cache.record_count(), 256);
    assert_eq!(
        cache.lookup_exact(0x1080).next().unwrap().kind,
        RecordKind::Selector
    );
    assert_eq!(
        cache
            .lookup_exact(0x1fe000)
            .next()
            .unwrap()
            .section
            .macho_ordinal,
        255
    );
    assert!(matches!(
        DataCache::parse(
            built.as_bytes(),
            ReadLimits {
                sections: 255,
                ..ReadLimits::default()
            }
        ),
        Err(crate::ParseError::Limit("table count"))
    ));
}

fn chained_fixup_source(slots: usize) -> Vec<u8> {
    let per_page = 2048usize;
    let pages = slots.div_ceil(per_page);
    let file_size = pages * 16384;
    let info_size = 22 + pages * 2;
    let blob_offset = 0x1000 + file_size;
    let mut source = data_symbol_fixture(
        BASE,
        &[data_section(
            "__DATA",
            "__data",
            BASE + 0x1000,
            file_size as u64,
            0,
        )],
        &[("_sentinel", symbols::N_SECT, 1, BASE + 0x1000)],
        Some(UUID),
    );
    let mut command = vec![0; 16];
    write_u32(&mut command, 0, 0x8000_0034);
    write_u32(&mut command, 4, 16);
    write_u32(&mut command, 8, blob_offset as u32);
    write_u32(&mut command, 12, (40 + info_size) as u32);
    append_load_command(&mut source, &command);
    write_u64(&mut source, 104 + 40, 0x1000);
    write_u64(&mut source, 104 + 48, file_size as u64);
    source.resize(blob_offset, 0);
    for index in 0..slots {
        let next = u64::from(index + 1 < slots && (index + 1) % per_page != 0) * 2;
        write_u64(&mut source, 0x1000 + index * 8, next << 51);
    }
    let mut blob = vec![0; 40 + info_size];
    write_u32(&mut blob, 4, 28);
    write_u32(&mut blob, 28, 2);
    write_u32(&mut blob, 36, 12);
    write_u32(&mut blob, 40, info_size as u32);
    blob[44..46].copy_from_slice(&16384u16.to_le_bytes());
    blob[46..48].copy_from_slice(&6u16.to_le_bytes());
    write_u64(&mut blob, 48, 0x1000);
    blob[60..62].copy_from_slice(&(pages as u16).to_le_bytes());
    source.extend_from_slice(&blob);
    source
}

#[test]
fn chained_fixups_honor_configured_limits_above_one_million() {
    let slots = 1_000_001usize;
    let source = chained_fixup_source(slots);
    for (limit, expected) in [
        (slots as u64 - 1, State::Incomplete),
        (slots as u64, State::Complete),
        (u64::MAX, State::Complete),
    ] {
        let built = build(
            &source,
            BuildLimits {
                raw_symbols: limit,
                ..BuildLimits::default()
            },
        );
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        assert_eq!(
            cache.state(),
            expected,
            "limit {limit}: {:?}",
            cache.reason()
        );
        assert_eq!(
            cache.record_count(),
            usize::from(expected == State::Complete)
        );
        if expected == State::Incomplete {
            assert_eq!(cache.reason(), Reason::RawSymbolLimit);
        }
    }
}

#[test]
fn chained_fixup_structure_rejects_invalid_pages_tables_and_file_ranges() {
    let source = chained_fixup_source(2);
    let command = 32 + read_u32(&source, 20) as usize - 16;
    let blob = read_u32(&source, command + 8) as usize;
    for case in 0..7 {
        let mut malformed = source.clone();
        match case {
            0 => write_u32(&mut malformed, command + 12, 39),
            1 => write_u64(&mut malformed, blob + 48, 0x2000),
            2 => malformed[blob + 62..blob + 64].copy_from_slice(&16380u16.to_le_bytes()),
            3 => malformed[blob + 62..blob + 64].copy_from_slice(&0x8000u16.to_le_bytes()),
            4 => malformed[blob + 62..blob + 64].copy_from_slice(&0x8002u16.to_le_bytes()),
            5 => write_u64(&mut malformed, 0x1000, 4095u64 << 51),
            6 => write_u64(&mut malformed, 104 + 48, 8),
            _ => unreachable!(),
        }
        let built = build(&malformed, BuildLimits::default());
        let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
        assert_eq!(cache.reason(), Reason::SourceError, "case {case}");
        assert_eq!(cache.record_count(), 0, "case {case}");
    }
}

#[test]
fn chained_fixup_overflow_lists_preserve_distinct_starts_and_reject_duplicate_slots() {
    let mut source = chained_fixup_source(2);
    let command = 32 + read_u32(&source, 20) as usize - 16;
    let blob = read_u32(&source, command + 8) as usize;
    let blob_size = read_u32(&source, command + 12);
    source.resize(source.len() + 4, 0);
    write_u32(&mut source, command + 12, blob_size + 4);
    write_u32(&mut source, blob + 40, 28);
    write_u64(&mut source, 0x1000, 0);
    source[blob + 62..blob + 64].copy_from_slice(&0x8001u16.to_le_bytes());
    source[blob + 66..blob + 68].copy_from_slice(&0x8008u16.to_le_bytes());
    let built = build(&source, BuildLimits::default());
    assert_eq!(built.state(), State::Complete);
    assert_eq!(
        DataCache::parse(built.as_bytes(), ReadLimits::default())
            .unwrap()
            .record_count(),
        1
    );
    source[blob + 66..blob + 68].copy_from_slice(&0x8000u16.to_le_bytes());
    let rejected = build(&source, BuildLimits::default());
    assert_eq!(rejected.reason(), Reason::SourceError);
    assert_eq!(
        DataCache::parse(rejected.as_bytes(), ReadLimits::default())
            .unwrap()
            .record_count(),
        0
    );
}
