//! Recover qualified Swift type-descriptor names from `__swift5_types` roots.
//!
//! Swift ABI references here are signed 32-bit displacements from their own field addresses, not
//! Mach-O absolute pointers. Descriptor flags select the fixed prefix we can safely describe; parent
//! contexts build a display name without implying that an allocation is an instance of that type.

use super::Image;
use crate::{Reason, RecordKind};

impl Image<'_, '_> {
    /// Resolve RelativeDirectPointer or RelativeIndirectablePointer: zero means absent, and for
    /// indirectable references low bit 1 means the relative target is a pointer slot to follow.
    /// Clear the tag before sign-extending the displacement so backward references remain backward.
    fn relative(&self, address: u64, indirect: bool) -> Option<u64> {
        let delta = self.u32(address)? as i32;
        if delta == 0 {
            return None;
        }
        let target =
            address.checked_add_signed(i64::from(if indirect { delta & !1 } else { delta }))?;
        if indirect && delta & 1 != 0 {
            self.pointer(target)
        } else {
            Some(target)
        }
    }

    /// Walk one bounded parent chain. Flags/parent/name occupy +0/+4/+8 in the accepted contexts;
    /// require the whole chain to be understood rather than returning an unqualified partial name.
    fn swift_name(&mut self, address: u64, seen: &mut Vec<u64>) -> Result<Option<String>, Reason> {
        if seen.len() >= 32 || seen.contains(&address) || self.section(address, 12).is_none() {
            return Ok(None);
        }
        self.step()?;
        seen.push(address);
        // ContextDescriptorKind is the low five flag bits: Module=0, Anonymous=3, Class=16,
        // Struct=17, Enum=18. Other descriptor kinds have layouts this reader does not interpret.
        if !self
            .u32(address)
            .is_some_and(|flags| matches!(flags & 31, 0 | 3 | 16 | 17 | 18))
        {
            return Ok(None);
        }
        let Some(name) = self
            .relative(address + 8, false)
            .and_then(|pointer| self.name(pointer))
        else {
            return Ok(None);
        };
        let parent = match self.relative(address + 4, true) {
            Some(parent) => match self.swift_name(parent, seen)? {
                Some(parent) => Some(parent),
                None => return Ok(None),
            },
            None => None,
        };
        let length = name
            .len()
            .saturating_add(parent.as_ref().map_or(0, |parent| parent.len() + 1));
        if length > self.limits.name_length {
            return Err(Reason::NameLengthLimit);
        }
        self.storage.charge(length)?;
        Ok(Some(match parent {
            Some(parent) => format!("{parent}.{name}"),
            None => name.to_owned(),
        }))
    }

    /// The root section is an array of 4-byte relative-indirectable descriptor references.
    pub(super) fn swift(&mut self) -> Result<(), Reason> {
        for (start, count) in self.roots(&["__swift5_types"], 4) {
            for index in 0..count {
                self.step()?;
                let Some(address) = self.relative(start + index * 4, true) else {
                    continue;
                };
                let Some(kind) = self.u32(address).map(|flags| flags & 31) else {
                    continue;
                };
                // Require the known fixed class (44-byte) or struct/enum (28-byte) descriptor.
                // Generic contexts, field records, and variable trailing payloads are not traversed.
                let size = match kind {
                    16 => 44,
                    17 | 18 => 28,
                    _ => continue,
                };
                if self.section(address, size).is_none() {
                    continue;
                }
                let Some(name) = self.swift_name(address, &mut Vec::with_capacity(32))? else {
                    continue;
                };
                self.add(address, RecordKind::SwiftTypeDescriptor, &name, None)?;
                // The common type prefix adds access-function and field-descriptor references at
                // +12/+16. Label the reference slots, not the code or field records they point to.
                for (delta, field) in [
                    (4, "parent"),
                    (8, "name"),
                    (12, "access_function"),
                    (16, "fields"),
                ] {
                    self.add(
                        address + delta,
                        RecordKind::SwiftTypeDescriptorField,
                        &name,
                        Some(field),
                    )?;
                }
            }
        }
        Ok(())
    }
}
