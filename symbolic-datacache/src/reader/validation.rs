use super::DataCache;
use crate::format::{read_u32, read_u64};
use crate::{ParseError, ReadLimits, State};

impl DataCache<'_> {
    pub(super) fn validate(&self, limits: ReadLimits) -> Result<(), ParseError> {
        if self.records.len() as u64 > self.statistics.accepted_records
            || (self.state == State::Complete
                && self.records.len() == 0
                && self.statistics.accepted_records != 0)
        {
            return Err(ParseError::Identity);
        }
        let mut previous_ordinal = 0;
        for index in 0..self.sections.len() {
            let section = self.section(index)?;
            if section.macho_ordinal <= previous_ordinal || section.macho_ordinal > 255 {
                return Err(ParseError::Ordering);
            }
            if section.size == 0
                || section.address.checked_add(section.size).is_none()
                || section.segment_name.len() > 16
                || section.name.len() > 16
            {
                return Err(ParseError::Reference);
            }
            previous_ordinal = section.macho_ordinal;
        }
        let mut previous_address = None;
        let mut next_record = 0;
        let mut name_bytes = 0u64;
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
            if count == 0
                || first != next_record
                || previous_address.is_some_and(|prev| prev >= address)
            {
                return Err(ParseError::Ordering);
            }
            let mut previous_alias = None;
            for record in first..end {
                let row = self.records.row(record);
                if read_u32(row, 12) != 0 {
                    return Err(ParseError::Reference);
                }
                let section = self.section(read_u32(row, 0) as usize)?;
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
                let alias = (section.macho_ordinal, name);
                if previous_alias.is_some_and(|previous| previous >= alias) {
                    return Err(ParseError::Ordering);
                }
                previous_alias = Some(alias);
            }
            previous_address = Some(address);
            next_record = end;
        }
        if next_record != self.records.len() {
            return Err(ParseError::Reference);
        }
        Ok(())
    }
}
