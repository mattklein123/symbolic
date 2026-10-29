//! Prove the semantic invariants behind zero-copy exact lookup after byte/table bounds are checked.
//!
//! Address groups must partition all aliases in canonical order, and every alias must point into its
//! own section. Reject unknown provenance and inconsistent raw counters instead of salvaging records.

use super::DataCache;
use crate::format::{read_u32, read_u64};
use crate::{ParseError, ReadLimits, RecordKind, State};

impl DataCache<'_> {
    pub(super) fn validate(&self, limits: ReadLimits) -> Result<(), ParseError> {
        // All v1 records are raw. v2 may contain more derived records than accepted nlist entries,
        // so its raw-only counter comparison is deferred until kinds have been checked below.
        if (self.version == 1 && self.records.len() as u64 > self.statistics.accepted_records)
            || (self.state == State::Complete
                && self.records.len() == 0
                && self.statistics.accepted_records != 0)
        {
            return Err(ParseError::Identity);
        }
        let mut previous_ordinal = None;
        for index in 0..self.sections.len() {
            let section = self.section(index)?;
            if previous_ordinal.is_some_and(|previous| section.macho_ordinal <= previous)
                || section.macho_ordinal > 255
            {
                return Err(ParseError::Ordering);
            }
            if section.macho_ordinal == 0
                && (self.version != 2
                    || section.segment_name != "__OBJC_RO"
                    || section.name != "__selectors"
                    || section.flags != 0)
            {
                return Err(ParseError::Reference);
            }
            if section.size == 0
                || section.address.checked_add(section.size).is_none()
                || section.segment_name.len() > 16
                || section.name.len() > 16
            {
                return Err(ParseError::Reference);
            }
            previous_ordinal = Some(section.macho_ordinal);
        }
        let mut previous_address = None;
        let mut next_record = 0;
        let mut name_bytes = 0u64;
        let mut raw_records = 0u64;
        for index in 0..self.addresses.len() {
            let row = self.addresses.row(index);
            let address = read_u64(row, 0);
            let first = read_u32(row, 8) as usize;
            let count = read_u32(row, 12) as usize;
            if count as u64 > limits.aliases {
                return Err(ParseError::Limit("aliases"));
            }
            let end = first
                .checked_add(count)
                .filter(|end| *end <= self.records.len())
                .ok_or(ParseError::Reference)?;
            // Strictly increasing address rows and contiguous, nonempty groups rule out overlapping
            // alias ranges, unreachable prefixes, and multiple groups competing for the same key.
            if count == 0
                || first != next_record
                || previous_address.is_some_and(|prev| prev >= address)
            {
                return Err(ParseError::Ordering);
            }
            let mut previous_alias = None;
            for record in first..end {
                let row = self.records.row(record);
                let kind = RecordKind::from_u32(read_u32(row, 12))?;
                // Function is still an original nlist record, not a derived metadata description.
                // Deduplication may reduce this count, but cannot create more raw input records.
                if matches!(kind, RecordKind::Symbol | RecordKind::Function) {
                    raw_records += 1;
                }
                if self.version == 1 && kind != RecordKind::Symbol {
                    return Err(ParseError::Reference);
                }
                let section = self.section(read_u32(row, 0) as usize)?;
                if section.macho_ordinal == 0 && (kind != RecordKind::Selector || address & 7 != 0)
                {
                    return Err(ParseError::Reference);
                }
                let name = self.string(row, 4)?;
                name_bytes = name_bytes
                    .checked_add(name.len() as u64)
                    .ok_or(ParseError::Bounds)?;
                if name.len() as u64 > limits.name_length
                    || name_bytes > limits.referenced_name_bytes
                {
                    return Err(ParseError::Limit("symbol name bytes"));
                }
                if name.is_empty()
                    || name.as_bytes().contains(&0)
                    || address < section.address
                    || address - section.address >= section.size
                {
                    return Err(ParseError::Reference);
                }
                // Match writer order exactly. Equal tuples are duplicate records, while different
                // kinds at the same address/name remain meaningful aliases for caller ambiguity checks.
                let alias = (section.macho_ordinal, name, kind);
                if previous_alias.is_some_and(|previous| previous >= alias) {
                    return Err(ParseError::Ordering);
                }
                previous_alias = Some(alias);
            }
            previous_address = Some(address);
            next_record = end;
        }
        if raw_records > self.statistics.accepted_records {
            return Err(ParseError::Identity);
        }
        if next_record != self.records.len() {
            return Err(ParseError::Reference);
        }
        Ok(())
    }
}
