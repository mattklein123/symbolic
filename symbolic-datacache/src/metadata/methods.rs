//! Method context comes only from validated class roots, never synthetic nlist entries or proximity.

use super::Image;
use crate::{Reason, RecordKind};

impl Image<'_, '_> {
    pub(super) fn methods(
        &mut self,
        address: u64,
        owner: &str,
        metaclass: bool,
        depth: usize,
    ) -> Result<(), Reason> {
        self.step()?;
        if address == 0 || depth >= 8 {
            return Ok(());
        }
        if (address & !1).checked_add(8).is_none() {
            return Ok(());
        }
        if address & 1 != 0 {
            let start = address & !1;
            let Some((8, count)) = self.u32(start).zip(self.u32(start + 4)) else {
                return Ok(());
            };
            if count > 10_000 || self.read(start, 8 + count as usize * 8).is_none() {
                return Ok(());
            }
            for index in 0..u64::from(count) {
                self.step()?;
                let entry = start + 8 + index * 8;
                let Some(packed) = self.pointer(entry) else {
                    continue;
                };
                if let Some(child) = entry.checked_add_signed((packed as i64) >> 16) {
                    self.methods(child, owner, metaclass, depth + 1)?;
                }
            }
            return Ok(());
        }
        if address & 3 != 0 {
            return Ok(());
        }
        let Some((flags, count)) = self.u32(address).zip(self.u32(address + 4)) else {
            return Ok(());
        };
        let relative = flags & 0x8000_0000 != 0;
        let width = if relative { 12 } else { 24 };
        if flags & 0xfffc != width
            || count > 100_000
            || self
                .section(address, 8 + count as usize * width as usize)
                .is_none()
        {
            return Ok(());
        }
        for index in 0..u64::from(count) {
            self.step()?;
            let entry = address + 8 + index * u64::from(width);
            let decoded = if relative {
                self.relative_method(entry, flags)
            } else {
                self.pointer(entry).zip(self.pointer(entry + 16))
            };
            let Some((selector, implementation)) = decoded else {
                continue;
            };
            let Some(selector) = self.name(selector) else {
                continue;
            };
            let length = owner.len().saturating_add(selector.len()).saturating_add(4);
            if length > self.limits.name_length {
                return Err(Reason::NameLengthLimit);
            }
            self.storage.charge(length)?;
            let sign = if metaclass { '+' } else { '-' };
            let name = format!("{sign}[{owner} {selector}]");
            if self
                .section(implementation, 1)
                .is_some_and(|section| section.flags & (0x8000_0000 | 0x400) != 0)
            {
                self.add(
                    implementation,
                    RecordKind::MethodImplementation,
                    &name,
                    None,
                )?;
            }
            let fields = if relative {
                [(0, "selector"), (4, "types"), (8, "implementation")]
            } else {
                [(0, "selector"), (8, "types"), (16, "implementation")]
            };
            for (delta, field) in fields {
                self.add(entry + delta, RecordKind::MethodEntry, &name, Some(field))?;
            }
        }
        Ok(())
    }

    fn relative_method(&self, entry: u64, flags: u32) -> Option<(u64, u64)> {
        let selector = if flags & 0x4000_0000 != 0 {
            self.context?
                .objc_selector_base()?
                .checked_add(u64::from(self.u32(entry)?))?
        } else {
            self.pointer(entry.checked_add_signed(i64::from(self.u32(entry)? as i32))?)?
        };
        let delta = self.u32(entry + 8)? as i32;
        if delta == 0 {
            return None;
        }
        Some((selector, (entry + 8).checked_add_signed(i64::from(delta))?))
    }
}
