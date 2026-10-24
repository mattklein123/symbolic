//! Small synthetic Mach-O fixtures with real nlist and section metadata, without file-backed data.

use goblin::mach::constants::cputype;
use goblin::mach::header::{self, Header64};
use goblin::mach::load_command::{self, Section64, SegmentCommand64, SymtabCommand, UuidCommand};
use goblin::mach::symbols::{self, Nlist64};
use scroll::{Pwrite, LE};

fn name_bytes(name: &str) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

/// A section with an absent file offset, as in a debug companion.
pub fn data_section(segment: &str, name: &str, address: u64, size: u64, flags: u32) -> Section64 {
    Section64 {
        sectname: name_bytes(name),
        segname: name_bytes(segment),
        addr: address,
        size,
        offset: u32::MAX,
        align: 0,
        reloff: 0,
        nreloc: 0,
        flags,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    }
}

/// Encodes arm64e dSYM metadata with optional UUID and caller-selected raw nlist entries.
/// Omitting the UUID preserves the original PR 3 fixture's exact command layout.
pub fn data_symbol_fixture(
    base: u64,
    sections: &[Section64],
    symbols: &[(&str, u8, u8, u64)],
    uuid: Option<[u8; 16]>,
) -> Vec<u8> {
    let segment_size = load_command::SIZEOF_SEGMENT_COMMAND_64;
    let command_size = segment_size + load_command::SIZEOF_SECTION_64;
    let uuid_size = if uuid.is_some() {
        load_command::SIZEOF_UUID_COMMAND
    } else {
        0
    };
    let commands_size = segment_size
        + command_size * sections.len()
        + load_command::SIZEOF_SYMTAB_COMMAND
        + uuid_size;
    let symbols_offset = header::SIZEOF_HEADER_64 + commands_size;
    let strings_offset = symbols_offset + symbols.len() * symbols::SIZEOF_NLIST_64;
    let mut strings = vec![0];
    let entries: Vec<_> = symbols
        .iter()
        .map(|(name, kind, ordinal, address)| {
            let entry = Nlist64 {
                n_strx: strings.len() as u32,
                n_type: *kind,
                n_sect: *ordinal,
                n_desc: 0,
                n_value: *address,
            };
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            entry
        })
        .collect();
    let mut bytes = vec![0; strings_offset + strings.len()];
    let mut offset = 0;
    bytes
        .gwrite_with(
            Header64 {
                magic: header::MH_MAGIC_64,
                cputype: cputype::CPU_TYPE_ARM64,
                cpusubtype: cputype::CPU_SUBTYPE_ARM64_E,
                filetype: header::MH_DSYM,
                ncmds: sections.len() as u32 + 2 + u32::from(uuid.is_some()),
                sizeofcmds: commands_size as u32,
                flags: 0,
                reserved: 0,
            },
            &mut offset,
            LE,
        )
        .unwrap();
    let segment = SegmentCommand64 {
        cmd: load_command::LC_SEGMENT_64,
        cmdsize: segment_size as u32,
        segname: name_bytes("__TEXT"),
        vmaddr: base,
        vmsize: 0,
        fileoff: 0,
        filesize: 0,
        maxprot: 0,
        initprot: 0,
        nsects: 0,
        flags: 0,
    };
    bytes.gwrite_with(segment, &mut offset, LE).unwrap();
    for section in sections {
        bytes
            .gwrite_with(
                SegmentCommand64 {
                    cmdsize: command_size as u32,
                    segname: section.segname,
                    vmaddr: section.addr,
                    vmsize: section.size,
                    nsects: 1,
                    ..segment
                },
                &mut offset,
                LE,
            )
            .unwrap();
        bytes.gwrite_with(*section, &mut offset, LE).unwrap();
    }
    if let Some(uuid) = uuid {
        bytes
            .gwrite_with(
                UuidCommand {
                    cmd: load_command::LC_UUID,
                    cmdsize: uuid_size as u32,
                    uuid,
                },
                &mut offset,
                LE,
            )
            .unwrap();
    }
    bytes
        .gwrite_with(
            SymtabCommand {
                cmd: load_command::LC_SYMTAB,
                cmdsize: load_command::SIZEOF_SYMTAB_COMMAND as u32,
                symoff: symbols_offset as u32,
                nsyms: entries.len() as u32,
                stroff: strings_offset as u32,
                strsize: strings.len() as u32,
            },
            &mut offset,
            LE,
        )
        .unwrap();
    for entry in entries {
        bytes.gwrite_with(entry, &mut offset, LE).unwrap();
    }
    bytes[offset..].copy_from_slice(&strings);
    bytes
}
