//! Index primary Itanium vtable address points rooted in original exact `_ZTV` symbols.

use super::Image;
use crate::{Reason, RecordKind};

impl Image<'_, '_> {
    pub(super) fn vtables(&mut self) -> Result<(), Reason> {
        let roots = self.records.len();
        for index in 0..roots {
            let record = &self.records[index];
            if record.kind != RecordKind::Symbol
                || !matches!(
                    record.section.segment_name.as_str(),
                    "__DATA" | "__DATA_CONST" | "__AUTH_CONST"
                )
                || record.section.name != "__const"
                || record.section.flags & (0x8000_0000 | 0x400) != 0
                || !record
                    .name
                    .strip_prefix("__ZTV")
                    .or_else(|| record.name.strip_prefix("_ZTV"))
                    .is_some_and(|name| !name.is_empty())
            {
                continue;
            }
            let Some(address) = self.base.checked_add(record.address) else {
                continue;
            };
            if address & 7 != 0 || self.section(address, 24).is_none() {
                continue;
            }
            let name = record.name.clone();
            self.step()?;

            // The primary table starts with offset-to-top and RTTI, then its first function slot.
            // Secondary/construction tables and virtual-base prefixes are not inferred from +16.
            if self.read(address, 8) != Some([0; 8].as_slice()) {
                continue;
            }
            let Some(rtti) = self.pointer(address + 8) else {
                continue;
            };
            if rtti != 0 && self.read(rtti, 16).is_none() {
                continue;
            }
            let Some(function) = self.pointer(address + 16) else {
                continue;
            };
            if !self
                .section(function, 1)
                .is_some_and(|section| section.flags & (0x8000_0000 | 0x400) != 0)
            {
                continue;
            }
            self.add(address + 16, RecordKind::CxxVtableAddressPoint, &name, None)?;
        }
        Ok(())
    }
}
