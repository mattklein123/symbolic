//! Decode on-disk `LC_DYLD_CHAINED_FIXUPS` before ABI readers follow metadata pointers.
//!
//! A fixup location contains a packed dyld instruction, not a directly dereferenceable address.
//! Rebase entries resolve inside the image; bind entries identify imports without inventing their
//! runtime addresses. Unsupported encodings skip metadata extraction, while malformed supported
//! encodings fail the build. The layouts below follow Apple's `mach-o/fixup-chains.h`.

use std::mem::size_of;

use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;

use crate::builder::StorageBudget;
use crate::{BuildLimits, Reason};

#[cfg(test)]
#[path = "fixups_test.rs"]
mod tests;

/// A decoded target, distinct from the virtual address of the slot containing the fixup.
pub(super) enum Pointer<'data> {
    Address(u64),
    /// Only zero addends permit treating the import as the named object itself.
    Import {
        name: &'data str,
        exact: bool,
    },
}

#[derive(Default)]
pub(super) struct Fixups<'data> {
    entries: Vec<(u64, Pointer<'data>)>,
    pub(super) examined_name_bytes: u64,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

impl<'data> Fixups<'data> {
    pub(super) fn get(&self, address: u64) -> Option<&Pointer<'data>> {
        self.entries
            .binary_search_by_key(&address, |entry| entry.0)
            .ok()
            .map(|index| &self.entries[index].1)
    }

    /// Index fixups by their slot's unslid virtual address for later metadata reads.
    /// `Some(empty)` means no fixup command; `None` means an unsupported encoding, not plain pointers.
    pub(super) fn parse(
        macho: &MachO<'data>,
        data: &'data [u8],
        base: u64,
        limits: BuildLimits,
        storage: &mut StorageBudget,
    ) -> Result<Option<Self>, Reason> {
        let mut result = Self::default();
        let Some(command) = macho
            .load_commands
            .iter()
            .find_map(|command| match &command.command {
                CommandVariant::DyldChainedFixups(command) => Some(command),
                _ => None,
            })
        else {
            return Ok(Some(result));
        };
        let start = command.dataoff as usize;
        let end = start
            .checked_add(command.datasize as usize)
            .ok_or(Reason::SourceError)?;
        let blob = data.get(start..end).ok_or(Reason::SourceError)?;
        // dyld_chained_fixups_header: version at +0, starts/imports/symbols offsets at +4/+8/+12,
        // import count/format at +16/+20, and symbol-pool encoding at +24. Only version 0 with an
        // uncompressed symbol pool is understood. All offsets are relative to this command blob.
        if u32_at(blob, 0) != Some(0) || u32_at(blob, 24) != Some(0) {
            return Ok(None);
        }
        let starts = u32_at(blob, 4).ok_or(Reason::SourceError)? as usize;
        let segment_count = u32_at(blob, starts).ok_or(Reason::SourceError)? as usize;
        if segment_count > macho.segments.len() || segment_count > 255 {
            return Err(Reason::SourceError);
        }
        for (index, segment) in macho.segments.iter().take(segment_count).enumerate() {
            // dyld_chained_starts_in_image parallels the Mach-O segment commands. A zero entry
            // means that segment has no fixups; nonzero offsets are relative to the starts table.
            let offset = u32_at(blob, starts + 4 + index * 4).ok_or(Reason::SourceError)? as usize;
            if offset == 0 {
                continue;
            }
            let offset = starts.checked_add(offset).ok_or(Reason::SourceError)?;
            let size = u32_at(blob, offset).ok_or(Reason::SourceError)? as usize;
            let info = blob
                .get(offset..offset.checked_add(size).ok_or(Reason::SourceError)?)
                .ok_or(Reason::SourceError)?;
            let page_size = u16_at(info, 4).ok_or(Reason::SourceError)?;
            let format = u16_at(info, 6).ok_or(Reason::SourceError)?;
            // DYLD_CHAINED_PTR_ARM64E=1, PTR_64=2, PTR_64_OFFSET=6, ARM64E_USERLAND=9,
            // ARM64E_USERLAND24=12. A starts-in-segment header has page_count at +20 and its
            // u16 page-start array at +22; segment_offset at +8 is relative to the image base.
            if !matches!(format, 1 | 2 | 6 | 9 | 12) || !matches!(page_size, 4096 | 16384) {
                return Ok(None);
            }
            let segment_offset = u64_at(info, 8).ok_or(Reason::SourceError)?;
            if base.checked_add(segment_offset) != Some(segment.vmaddr) {
                return Err(Reason::SourceError);
            }
            let page_count = u16_at(info, 20).ok_or(Reason::SourceError)? as usize;
            if info.len() < 22 + page_count * 2 {
                return Err(Reason::SourceError);
            }
            for page in 0..page_count {
                let chain = u16_at(info, 22 + page * 2).ok_or(Reason::SourceError)?;
                // START_NONE is 0xffff. Otherwise bit 15 selects an overflow list containing
                // multiple starts on this page; that list uses bit 15 to mark its final entry.
                if chain == 0xffff {
                    continue;
                }
                let mut overflow = usize::from(chain & 0x7fff);
                let mut chain_start = chain;
                loop {
                    let mut last = true;
                    if chain & 0x8000 != 0 {
                        if overflow < page_count {
                            return Err(Reason::SourceError);
                        }
                        chain_start = u16_at(info, 22 + overflow * 2).ok_or(Reason::SourceError)?;
                        last = chain_start & 0x8000 != 0;
                        overflow += 1;
                    }
                    let mut within = u64::from(chain_start & 0x7fff);
                    loop {
                        // Chains may advance only within their declared page and file-backed
                        // segment. The next-link stride must never turn into an arbitrary VM read.
                        if within + 8 > u64::from(page_size) {
                            return Err(Reason::SourceError);
                        }
                        if result.entries.len() as u64 >= limits.raw_symbols {
                            return Err(Reason::RawSymbolLimit);
                        }
                        let relative = (page as u64)
                            .checked_mul(u64::from(page_size))
                            .and_then(|offset| offset.checked_add(within))
                            .ok_or(Reason::SourceError)?;
                        if relative
                            .checked_add(8)
                            .is_none_or(|end| end > segment.filesize)
                        {
                            return Err(Reason::SourceError);
                        }
                        let file_offset = segment
                            .fileoff
                            .checked_add(relative)
                            .and_then(|offset| usize::try_from(offset).ok())
                            .ok_or(Reason::SourceError)?;
                        let word = u64_at(data, file_offset).ok_or(Reason::SourceError)?;
                        let (pointer, next) =
                            Self::decode(word, format, base, blob, limits.name_length)?;
                        if let Pointer::Import { name, .. } = &pointer {
                            result.examined_name_bytes = result
                                .examined_name_bytes
                                .checked_add(name.len() as u64 + 1)
                                .filter(|bytes| *bytes <= limits.examined_name_bytes)
                                .ok_or(Reason::ExaminedNameBytesLimit)?;
                        }
                        if result.entries.len() == result.entries.capacity() {
                            let capacity = result.entries.capacity().saturating_mul(2).max(16);
                            storage.charge(
                                capacity
                                    .checked_mul(size_of::<(u64, Pointer<'_>)>())
                                    .ok_or(Reason::BuilderMemoryLimit)?,
                            )?;
                            result
                                .entries
                                .try_reserve_exact(capacity - result.entries.len())
                                .map_err(|_| Reason::BuilderMemoryLimit)?;
                        }
                        result.entries.push((
                            segment
                                .vmaddr
                                .checked_add(relative)
                                .ok_or(Reason::SourceError)?,
                            pointer,
                        ));
                        if next == 0 {
                            break;
                        }
                        within = within.checked_add(next).ok_or(Reason::SourceError)?;
                    }
                    if last {
                        break;
                    }
                }
            }
        }
        // Segment/page traversal order is not a lookup contract. Reject duplicate slots rather
        // than allowing binary search to choose one of two conflicting pointer interpretations.
        result.entries.sort_unstable_by_key(|entry| entry.0);
        if result.entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Reason::SourceError);
        }
        Ok(Some(result))
    }

    /// Return the decoded target and the byte distance to the next slot (zero ends the chain).
    fn decode(
        word: u64,
        format: u16,
        base: u64,
        blob: &'data [u8],
        name_limit: usize,
    ) -> Result<(Pointer<'data>, u64), Reason> {
        let arm64e = matches!(format, 1 | 9 | 12);
        // ARM64E uses auth/bind bits 63/62 and an 11-bit next field with an 8-byte stride.
        // PTR_64 uses bind bit 63 and a 12-bit next field with a 4-byte stride.
        let bind = word & (1 << if arm64e { 62 } else { 63 }) != 0;
        let next = if arm64e {
            ((word >> 51) & 0x7ff) * 8
        } else {
            ((word >> 51) & 0xfff) * 4
        };
        if bind {
            // The low ordinal indexes the imports table, not a Mach-O symbol-table entry.
            // USERLAND24 widens ARM64E's ordinal from 16 to 24 bits; PTR_64 also uses 24 bits.
            let ordinal = word
                & if format == 12 {
                    0xff_ffff
                } else if arm64e {
                    0xffff
                } else {
                    0xff_ffff
                };
            let count = u32_at(blob, 16).ok_or(Reason::SourceError)? as u64;
            if ordinal >= count {
                return Err(Reason::SourceError);
            }
            let imports = u32_at(blob, 8).ok_or(Reason::SourceError)? as usize;
            let symbols = u32_at(blob, 12).ok_or(Reason::SourceError)? as usize;
            let import_format = u32_at(blob, 20).ok_or(Reason::SourceError)?;
            // IMPORT packs flags/ordinal/name offset into 4 bytes; IMPORT_ADDEND appends an i32;
            // IMPORT_ADDEND64 uses an 8-byte header followed by an i64. Only the name and whether
            // each addend is zero matter here, so signed addends need not be arithmetically applied.
            let (width, name_shift) = match import_format {
                1 => (4, 9),
                2 => (8, 9),
                3 => (16, 32),
                _ => return Err(Reason::SourceError),
            };
            let import = imports
                .checked_add(ordinal as usize * width)
                .ok_or(Reason::SourceError)?;
            let import_addend = match import_format {
                1 => 0,
                2 => u32_at(blob, import + 4).ok_or(Reason::SourceError)? as u64,
                3 => u64_at(blob, import + 8).ok_or(Reason::SourceError)?,
                _ => return Err(Reason::SourceError),
            };
            let pointer_addend = if arm64e {
                // Authenticated binds have no inline addend. Unauthenticated ARM64E binds use
                // bits 32..50; PTR_64 binds use bits 24..31.
                if word >> 63 != 0 {
                    0
                } else {
                    (word >> 32) & 0x7ffff
                }
            } else {
                (word >> 24) & 0xff
            };
            let offset = if name_shift == 32 {
                u32_at(blob, import + 4).ok_or(Reason::SourceError)?
            } else {
                u32_at(blob, import).ok_or(Reason::SourceError)? >> name_shift
            };
            let start = symbols
                .checked_add(offset as usize)
                .ok_or(Reason::SourceError)?;
            let tail = blob.get(start..).ok_or(Reason::SourceError)?;
            let length = tail
                .iter()
                .take(name_limit.saturating_add(1))
                .position(|byte| *byte == 0)
                .ok_or(Reason::NameLengthLimit)?;
            let name = std::str::from_utf8(&tail[..length]).map_err(|_| Reason::SourceError)?;
            return Ok((
                Pointer::Import {
                    name,
                    // Even cancelling nonzero addends are rejected: an import identity is useful
                    // only when both the import-table entry and pointer name the object exactly.
                    exact: import_addend == 0 && pointer_addend == 0,
                },
                next,
            ));
        }
        // Authenticated rebases store a 32-bit image-relative target; PAC key/diversity bits are
        // not part of its address. Other rebases reconstruct low target bits plus high8. OFFSET
        // and USERLAND formats need the image base, whereas formats 1/2 store absolute targets.
        let address = if arm64e && word >> 63 != 0 {
            base.checked_add(word & 0xffff_ffff)
                .ok_or(Reason::SourceError)?
        } else {
            let (target, high) = if arm64e {
                (word & 0x7ff_ffff_ffff, (word >> 43) & 0xff)
            } else {
                (word & 0xf_ffff_ffff, (word >> 36) & 0xff)
            };
            let target = if matches!(format, 6 | 9 | 12) {
                base.checked_add(target).ok_or(Reason::SourceError)?
            } else {
                target
            };
            target | high << 56
        };
        Ok((Pointer::Address(address), next))
    }
}
