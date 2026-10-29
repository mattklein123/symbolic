//! Index pointer-aligned exact selector-table members owned by this image's declared selector pool.
//!
//! Version 0 places 256 scramble words after its 32-byte header, followed by the mask-sized tab,
//! capacity-sized check bytes, and signed table-relative i32 string offsets.

use super::Image;
use crate::{Reason, RecordKind};

impl Image<'_, '_> {
    pub(super) fn selectors(&mut self) -> Result<(), Reason> {
        let Some(pool) = self.selector_pool.clone() else {
            return Ok(());
        };
        let Some(table) = self
            .context
            .and_then(|context| context.objc_selector_table())
        else {
            return Ok(());
        };
        let Some(header) = self.read(table, 32) else {
            return Ok(());
        };
        let [version, capacity, occupied, shift, mask] = std::array::from_fn(|index| {
            let offset = index * 4;
            u32::from_le_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        });
        let slot_limit = self
            .limits
            .raw_symbols
            .checked_next_power_of_two()
            .unwrap_or(u64::MAX)
            .min(1 << 22);
        if version != 0
            || !capacity.is_power_of_two()
            || occupied > capacity
            || shift > 64
            || u64::from(mask) >= slot_limit
        {
            return Ok(());
        }
        if u64::from(capacity) > slot_limit {
            return Err(Reason::RawSymbolLimit);
        }
        let offset = 1056u64 + u64::from(mask) + 1 + u64::from(capacity);
        let Some(offsets) = table
            .checked_add(offset)
            .and_then(|address| self.read(address, capacity as usize * 4))
        else {
            return Ok(());
        };
        let populated = offsets
            .chunks_exact(4)
            .filter(|bytes| **bytes != [0; 4])
            .count();
        if populated != occupied as usize {
            return Ok(());
        }
        let pool_start = self.base + pool.address;
        let pool_end = pool_start + pool.size;
        for bytes in offsets.chunks_exact(4) {
            let delta = i32::from_le_bytes(bytes.try_into().map_err(|_| Reason::SourceError)?);
            if delta == 0 {
                continue;
            }
            let Some(address) = table.checked_add_signed(i64::from(delta)) else {
                continue;
            };
            if address & 7 != 0 || address < pool_start || address >= pool_end {
                continue;
            }
            self.step()?;
            let Some(name) = self.name(address) else {
                continue;
            };
            if (address - pool_start)
                .checked_add(name.len() as u64 + 1)
                .is_some_and(|end| end <= pool.size)
            {
                self.add(address, RecordKind::Selector, name, None)?;
            }
        }
        Ok(())
    }
}
