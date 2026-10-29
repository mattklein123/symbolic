//! Canonicalize raw/derived records into address, alias, section, and string-pool tables.
//!
//! Stable ordering makes identical input produce identical bytes without hash-map iteration order.
//! Payload v2 reuses v1's reserved record word for provenance; widths and all other table layouts
//! stay unchanged. All integer fields are explicitly little-endian, never native Rust struct dumps.

use std::mem::size_of;
use std::sync::Arc;

use symbolic_debuginfo::macho::MachODataSection;

use crate::builder::{Record, StorageBudget};
use crate::format::{align, digest, write_u32, write_u64, HEADER_SIZE, WIDTHS};
use crate::{BuildLimits, Reason, RecordKind};

fn string_reference(bytes: &mut [u8], position: usize, name: &str, strings: &[(&str, u32)]) {
    let index = strings
        .binary_search_by_key(&name, |entry| entry.0)
        .unwrap_or_else(|_| unreachable!("builder interned all record and section names"));
    write_u32(bytes, position, strings[index].1);
    write_u32(bytes, position + 4, name.len() as u32);
}

/// Fill a builder-owned empty header only after the complete layout fits all construction budgets.
pub fn encode(
    bytes: &mut Vec<u8>,
    mut records: Vec<Record<'_>>,
    limits: BuildLimits,
    storage: &mut StorageBudget,
) -> Result<(), Reason> {
    if records.is_empty() {
        return Ok(());
    }
    // Keep distinct interpretations at one address, even when their labels match. The reader
    // validates this same (address, ordinal, name, kind) order and exposes the entire alias group.
    records.sort_unstable_by(|left, right| {
        (left.address, left.section.index, &*left.name, left.kind).cmp(&(
            right.address,
            right.section.index,
            &*right.name,
            right.kind,
        ))
    });
    // Charge aliases before deduplication: repeating a record cannot bypass the input-work bound.
    let mut previous_address = None;
    let mut aliases = 0;
    for record in &records {
        aliases = if previous_address == Some(record.address) {
            aliases + 1
        } else {
            1
        };
        if aliases > limits.aliases {
            return Err(Reason::AliasLimit);
        }
        previous_address = Some(record.address);
    }
    records.dedup_by(|left, right| {
        left.address == right.address
            && left.section.index == right.section.index
            && left.name == right.name
            && left.kind == right.kind
    });
    // Raw-data-only output remains byte-compatible v1. Any typed record requires v2; a former
    // reserved u32 at record +12 now stores RecordKind without changing the 16-byte row size.
    if records
        .iter()
        .any(|record| record.kind != RecordKind::Symbol)
    {
        write_u32(bytes, 8, 2);
    }
    let mut sections: Vec<Arc<MachODataSection>> = Vec::new();
    storage.charge(256 * size_of::<Arc<MachODataSection>>())?;
    sections
        .try_reserve_exact(256)
        .map_err(|_| Reason::BuilderMemoryLimit)?;
    for record in &records {
        if !sections
            .iter()
            .any(|section| section.index == record.section.index)
        {
            sections.push(Arc::clone(&record.section));
        }
    }
    sections.sort_unstable_by_key(|section| section.index);
    // Intern complete UTF-8 strings in lexical order. References are pool-relative byte offset/length
    // pairs, with no trailing NUL and no dependence on object or context lifetimes after encoding.
    let intern_count = records
        .len()
        .checked_add(sections.len() * 2)
        .ok_or(Reason::BuilderMemoryLimit)?;
    storage.charge(
        intern_count
            .checked_mul(size_of::<(&str, u32)>())
            .ok_or(Reason::BuilderMemoryLimit)?,
    )?;
    let mut strings = Vec::new();
    strings
        .try_reserve_exact(intern_count)
        .map_err(|_| Reason::BuilderMemoryLimit)?;
    strings.extend(records.iter().map(|record| (record.name.as_ref(), 0u32)));
    for section in &sections {
        strings.extend([
            (section.segment_name.as_str(), 0),
            (section.name.as_str(), 0),
        ]);
    }
    strings.sort_unstable_by_key(|entry| entry.0);
    strings.dedup_by_key(|entry| entry.0);
    let mut string_size = 0usize;
    for entry in &mut strings {
        entry.1 = u32::try_from(string_size).map_err(|_| Reason::StringPoolLimit)?;
        string_size = string_size
            .checked_add(entry.0.len())
            .ok_or(Reason::StringPoolLimit)?;
        if string_size as u64 > limits.string_bytes {
            return Err(Reason::StringPoolLimit);
        }
    }
    let address_count = records
        .iter()
        .enumerate()
        .filter(|(index, record)| *index == 0 || record.address != records[index - 1].address)
        .count();
    // Header descriptors at +128 contain (offset, count) pairs for address/record/section/string
    // tables. Table widths are 16/16/40/1 bytes; align each table before calculating its next end.
    let counts = [address_count, records.len(), sections.len(), string_size];
    let mut offsets = [0; 4];
    let mut file_size = HEADER_SIZE;
    for index in 0..4 {
        offsets[index] = align(file_size).ok_or(Reason::FileSizeLimit)?;
        file_size = counts[index]
            .checked_mul(WIDTHS[index])
            .and_then(|size| offsets[index].checked_add(size))
            .ok_or(Reason::FileSizeLimit)?;
    }
    if file_size as u64 > limits.file_bytes
        || string_size > u32::MAX as usize
        || records.len() > u32::MAX as usize
    {
        return Err(Reason::FileSizeLimit);
    }
    storage.charge(file_size - HEADER_SIZE)?;
    bytes
        .try_reserve_exact(file_size - bytes.len())
        .map_err(|_| Reason::BuilderMemoryLimit)?;
    bytes.resize(file_size, 0);
    write_u64(bytes, 16, file_size as u64);
    for index in 0..4 {
        write_u64(bytes, 128 + index * 16, offsets[index] as u64);
        write_u64(bytes, 136 + index * 16, counts[index] as u64);
    }
    // Address rows store u64 relative address, u32 first-record index, and u32 alias count. Groups
    // partition the record table, enabling exact binary search without expanding a runtime map.
    let mut address_row = 0;
    let mut first_record = 0;
    while first_record < records.len() {
        let address = records[first_record].address;
        let mut end = first_record + 1;
        while end < records.len() && records[end].address == address {
            end += 1;
        }
        let position = offsets[0] + address_row * 16;
        write_u64(bytes, position, address);
        write_u32(bytes, position + 8, first_record as u32);
        write_u32(bytes, position + 12, (end - first_record) as u32);
        first_record = end;
        address_row += 1;
    }
    // Alias rows reference the compact section table, then a string offset/length, then record kind.
    for (index, record) in records.iter().enumerate() {
        let position = offsets[1] + index * 16;
        let section = sections
            .binary_search_by_key(&record.section.index, |section| section.index)
            .map_err(|_| Reason::SourceError)?;
        write_u32(bytes, position, section as u32);
        string_reference(bytes, position + 4, &record.name, &strings);
        write_u32(bytes, position + 12, record.kind as u32);
    }
    // Section rows preserve relative start/size, original n_sect/flags, and segment/section names.
    // The compact section index above is deliberately not the original Mach-O ordinal.
    for (index, section) in sections.iter().enumerate() {
        let position = offsets[2] + index * 40;
        write_u64(bytes, position, section.address);
        write_u64(bytes, position + 8, section.size);
        write_u32(bytes, position + 16, u32::from(section.index));
        write_u32(bytes, position + 20, section.flags);
        string_reference(bytes, position + 24, &section.segment_name, &strings);
        string_reference(bytes, position + 32, &section.name, &strings);
    }
    for (name, offset) in strings {
        let start = offsets[3] + offset as usize;
        bytes[start..start + name.len()].copy_from_slice(name.as_bytes());
    }
    // Hash only the completed payload. Source-slice identity has its separate header digest.
    let checksum = digest(&bytes[HEADER_SIZE..]);
    bytes[96..128].copy_from_slice(&checksum);
    Ok(())
}
