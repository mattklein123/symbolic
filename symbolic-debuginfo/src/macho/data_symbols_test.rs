use std::sync::Arc;

use goblin::mach::constants;
use goblin::mach::header;
use goblin::mach::load_command::{self, Section64, SegmentCommand64, SymtabCommand};
use goblin::mach::symbols::{self, Nlist64};
use scroll::{Pread, Pwrite, LE};
use symbolic_common::Arch;
use symbolic_testutils::macho::{data_section as section, data_symbol_fixture};

use super::{DataSymbolError, DataSymbolLimits, MachObject};
use crate::macho::BcSymbolMap;

const BASE: u64 = 0x1_0000_0000;

#[test]
fn bounded_extraction_counts_filtered_entries_and_name_work() {
    let bytes = fixture(
        &[],
        &[
            ("_skip", symbols::N_UNDF, 0, 0),
            ("_also_skip", symbols::N_UNDF, 0, 0),
        ],
    );
    let object = MachObject::parse(&bytes).unwrap();
    let limits = DataSymbolLimits {
        raw_symbols: 1,
        name_length: 100,
        name_bytes: 100,
    };
    let mut bounded = object.bounded_data_symbols(limits).unwrap();
    assert!(matches!(
        bounded.next(),
        Some(Err(DataSymbolError::RawSymbolLimit))
    ));
    assert_eq!(bounded.declared_symbols(), 2);
    assert_eq!(bounded.inspected_symbols(), 1);
    assert_eq!(bounded.examined_name_bytes(), 5);
    assert!(bounded.next().is_none());
    for (name_length, name_bytes, expected) in [(4, 100, "length"), (100, 4, "bytes")] {
        let mut bounded = object
            .bounded_data_symbols(DataSymbolLimits {
                raw_symbols: 2,
                name_length,
                name_bytes,
            })
            .unwrap();
        match (bounded.next().unwrap().unwrap_err(), expected) {
            (DataSymbolError::NameLengthLimit, "length")
            | (DataSymbolError::NameBytesLimit, "bytes") => {}
            result => panic!("unexpected bounded extraction result: {result:?}"),
        }
        assert!(bounded.next().is_none());
    }
    assert_eq!(object.data_symbols().unwrap().count(), 0);
}

fn fixture(sections: &[Section64], symbols: &[(&str, u8, u8, u64)]) -> Vec<u8> {
    data_symbol_fixture(BASE, sections, symbols, None)
}

#[test]
fn preserves_raw_class_data_aliases_and_u64_offsets() {
    let sections = [
        section("__TEXT", "__const", BASE, 0x100, 0),
        section("__DATA", "__objc_data", BASE + 0x2000, 0x100, 0),
        section("__DATA_CONST", "__const", BASE + 0x3000, 0x100, 0),
        section("__AUTH", "__data", BASE + 0x1_0000_0000, 0x100, 0),
        section("__AUTH_CONST", "__const", BASE + 6_498_870_784, 0x100, 0),
        section(
            "__DATA",
            "__bss",
            BASE + 0x4000,
            0x100,
            constants::S_ZEROFILL,
        ),
        section("__OBJC", "__class", BASE + 0x5000, 0x100, 0),
    ];
    let symbols = [
        ("__ZTS4Type", symbols::N_SECT, 1, BASE),
        (
            "_OBJC_CLASS_$_HeapClass",
            symbols::N_SECT | symbols::N_EXT,
            2,
            BASE + 0x2000,
        ),
        ("_class_alias", symbols::N_SECT, 2, BASE + 0x2000),
        ("__hidden#0_", symbols::N_SECT, 3, BASE + 0x30ff),
        ("_$s4TypeCN", symbols::N_SECT, 4, BASE + 0x1_0000_0000),
        ("_large", symbols::N_SECT, 5, BASE + 6_498_870_784),
        ("_zero_fill", symbols::N_SECT, 6, BASE + 0x4000),
        ("_legacy_class", symbols::N_SECT, 7, BASE + 0x5000),
    ];
    let bytes = fixture(&sections, &symbols);
    let object = MachObject::parse(&bytes).unwrap();
    let data = object
        .data_symbols()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(data.len(), symbols.len());
    for (record, (name, _, ordinal, address)) in data.iter().zip(symbols) {
        let expected = &sections[ordinal as usize - 1];
        assert_eq!(record.name, name);
        assert_eq!(record.address, address - BASE);
        assert_eq!(record.section.index, ordinal);
        assert_eq!(record.section.address, expected.addr - BASE);
        assert_eq!(record.section.size, expected.size);
        assert_eq!(record.section.flags, expected.flags);
        assert_eq!(
            record.section.segment_name.as_bytes(),
            expected.segname.split(|byte| *byte == 0).next().unwrap()
        );
        assert_eq!(
            record.section.name.as_bytes(),
            expected.sectname.split(|byte| *byte == 0).next().unwrap()
        );
        assert_eq!(record.arch, Arch::Arm64e);
    }
    assert!(Arc::ptr_eq(&data[1].section, &data[2].section));
    assert_eq!(object.symbols().count(), 0);
}

#[test]
fn excludes_code_debug_undefined_and_invalid_section_addresses() {
    let sections = [
        section("__DATA", "__objc_data", BASE + 0x100, 4, 0),
        section("__TEXT", "__text", BASE + 0x200, 4, 0),
        section(
            "__TEXT",
            "__custom_code",
            BASE + 0x300,
            4,
            constants::S_ATTR_PURE_INSTRUCTIONS,
        ),
        section(
            "__TEXT",
            "__mixed",
            BASE + 0x400,
            4,
            constants::S_ATTR_SOME_INSTRUCTIONS,
        ),
        section(
            "__TEXT",
            "__custom_stubs",
            BASE + 0x500,
            4,
            constants::S_SYMBOL_STUBS,
        ),
        section(
            "__TEXT",
            "__debug",
            BASE + 0x600,
            4,
            constants::S_ATTR_DEBUG,
        ),
        section("__DWARF", "__debug_info", BASE + 0x700, 4, 0),
        section("__LINKEDIT", "__data", BASE + 0x800, 4, 0),
        section("__DATA", "__empty", BASE + 0x900, 0, 0),
    ];
    let mut symbols = vec![
        ("_start", symbols::N_SECT, 1, BASE + 0x100),
        ("_last_byte", symbols::N_SECT, 1, BASE + 0x103),
        ("_end", symbols::N_SECT, 1, BASE + 0x104),
        ("_before", symbols::N_SECT, 1, BASE + 0xff),
        ("_underflow", symbols::N_SECT, 1, BASE - 1),
        (
            "_undefined",
            symbols::N_UNDF | symbols::N_EXT,
            1,
            BASE + 0x100,
        ),
        ("_absolute", symbols::N_ABS, 1, BASE + 0x100),
        ("_indirect", symbols::N_INDR, 1, BASE + 0x100),
        ("_debug", symbols::N_STAB | symbols::N_SECT, 1, BASE + 0x100),
        ("_no_section", symbols::N_SECT, 0, BASE + 0x100),
        ("_bad_section", symbols::N_SECT, 255, BASE + 0x100),
        ("", symbols::N_SECT, 1, BASE + 0x100),
    ];
    symbols.extend((2..=9).map(|ordinal| {
        (
            "_excluded",
            symbols::N_SECT,
            ordinal,
            sections[ordinal as usize - 1].addr,
        )
    }));
    let bytes = fixture(&sections, &symbols);
    let object = MachObject::parse(&bytes).unwrap();
    let data = object
        .data_symbols()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        data.iter().map(|record| record.name).collect::<Vec<_>>(),
        ["_start", "_last_byte"]
    );
    assert_eq!(
        data.iter().map(|record| record.address).collect::<Vec<_>>(),
        [0x100, 0x103]
    );
}

#[test]
fn rejects_overflowing_and_pre_base_sections() {
    for section in [
        section("__DATA", "__data", BASE - 1, 1, 0),
        section("__DATA", "__data", u64::MAX - 1, 4, 0),
    ] {
        let bytes = fixture(&[section], &[]);
        let object = MachObject::parse(&bytes).unwrap();
        assert!(object.data_symbols().is_err());
    }
}

#[test]
fn rejects_sections_outside_segment_or_with_overflowing_extent() {
    let original = section("__DATA", "__data", BASE + 0x1000, 0x100, 0);
    let section_offset = header::SIZEOF_HEADER_64 + 2 * load_command::SIZEOF_SEGMENT_COMMAND_64;
    for (address, size, segment_name) in [
        (BASE + 0xfff, 1, "__DATA"),
        (BASE + 0x1000, 0x101, "__DATA"),
        (u64::MAX, 1, "__DATA"),
        (BASE + 0x1000, 1, "__AUTH"),
    ] {
        let mut bytes = fixture(&[original], &[]);
        let updated = Section64 {
            addr: address,
            size,
            segname: section(segment_name, "", 0, 0, 0).segname,
            ..original
        };
        bytes.pwrite_with(updated, section_offset, LE).unwrap();
        let object = MachObject::parse(&bytes).unwrap();
        assert!(object.data_symbols().is_err());
    }
}

#[test]
fn reports_malformed_symbol_names_without_hiding_later_records() {
    let mut bytes = fixture(
        &[section("__DATA", "__data", BASE, 4, 0)],
        &[
            ("_invalid", symbols::N_SECT, 1, BASE),
            ("_valid", symbols::N_SECT, 1, BASE + 1),
        ],
    );
    let symbol_offset = header::SIZEOF_HEADER_64
        + 2 * load_command::SIZEOF_SEGMENT_COMMAND_64
        + load_command::SIZEOF_SECTION_64
        + load_command::SIZEOF_SYMTAB_COMMAND;
    let mut invalid: Nlist64 = bytes.pread_with(symbol_offset, LE).unwrap();
    invalid.n_strx = u32::MAX;
    bytes.pwrite_with(invalid, symbol_offset, LE).unwrap();
    let object = MachObject::parse(&bytes).unwrap();
    let mut data = object.data_symbols().unwrap();
    assert!(data.next().unwrap().is_err());
    assert_eq!(data.next().unwrap().unwrap().name, "_valid");
    assert!(data.next().is_none());
}

#[test]
fn rejects_section_headers_outside_command_and_unrepresentable_ordinals() {
    let original = section("__DATA", "__data", BASE, 4, 0);
    let mut bytes = fixture(&[original], &[]);
    let offset = header::SIZEOF_HEADER_64 + load_command::SIZEOF_SEGMENT_COMMAND_64;
    let mut segment: SegmentCommand64 = bytes.pread_with(offset, LE).unwrap();
    segment.nsects = 2;
    bytes.pwrite_with(segment, offset, LE).unwrap();
    let object = MachObject::parse(&bytes).unwrap();
    assert!(object.data_symbols().is_err());

    let bytes = fixture(&vec![original; 256], &[]);
    let object = MachObject::parse(&bytes).unwrap();
    assert!(object.data_symbols().is_err());
}

#[test]
fn rejects_names_outside_declared_string_table() {
    let mut bytes = fixture(
        &[section("__DATA", "__data", BASE, 4, 0)],
        &[("_outside_table", symbols::N_SECT, 1, BASE)],
    );
    let offset = header::SIZEOF_HEADER_64
        + 2 * load_command::SIZEOF_SEGMENT_COMMAND_64
        + load_command::SIZEOF_SECTION_64;
    let mut table: SymtabCommand = bytes.pread_with(offset, LE).unwrap();
    table.strsize = 1;
    bytes.pwrite_with(table, offset, LE).unwrap();
    let object = MachObject::parse(&bytes).unwrap();
    assert!(object.data_symbols().unwrap().next().unwrap().is_err());
}

#[test]
fn raw_names_do_not_change_with_bitcode_mapping() {
    let bytes = fixture(
        &[section("__DATA", "__data", BASE, 4, 0)],
        &[("__hidden#0_", symbols::N_SECT, 1, BASE)],
    );
    let mut object = MachObject::parse(&bytes).unwrap();
    object.load_symbolmap(BcSymbolMap::parse(b"BCSymbolMap Version: 2.0\nresolved\n").unwrap());
    assert_eq!(
        object.data_symbols().unwrap().next().unwrap().unwrap().name,
        "__hidden#0_"
    );
}
