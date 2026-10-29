//! Recover exact-address runtime descriptions from rooted, little-endian 64-bit Mach-O metadata.
//!
//! ABI readers start from declared pointer/descriptor sections rather than scanning arbitrary bytes
//! for plausible structures. Reads may consult a matching shared cache, but emitted records must
//! belong to this image. These records describe metadata artifacts, never allocation-instance types.
//! Budget failures invalidate the build; an individual structurally invalid candidate is skipped.

use std::borrow::Cow;
use std::cell::Cell;
use std::mem::size_of;
use std::sync::Arc;

use goblin::mach::MachO;
use symbolic_debuginfo::macho::{MachODataSection, MachObject};

use crate::builder::{Record, StorageBudget};
use crate::{BuildLimits, Reason, RecordKind};

#[path = "metadata/constants.rs"]
mod constants;
#[path = "metadata/fixups.rs"]
mod fixups;
#[path = "metadata/methods.rs"]
mod methods;
#[path = "metadata/objc.rs"]
mod objc;
#[path = "metadata/selectors.rs"]
mod selectors;
#[path = "metadata/strings.rs"]
mod strings;
#[path = "metadata/swift.rs"]
mod swift;

/// Immutable, ingestion-only virtual-address context, such as a matching dyld shared cache.
/// Addresses use the image's original VM coordinates, not process ASLR addresses. Implementations
/// must supply bytes and aliases from the same cache generation; lookup never needs this context.
pub trait AddressSpace {
    /// Returns exactly the requested bounded bytes, or no mapping.
    fn read(&self, address: u64, size: usize) -> Option<&[u8]>;

    /// Original exact symbol spelling, when available, for runtime-class validation.
    fn symbol_name(&self, address: u64) -> Option<&str>;

    /// Validated selector-reference base for optimized relative Objective-C method lists.
    fn objc_selector_base(&self) -> Option<u64> {
        None
    }

    /// Address of the declared shared-cache selector hash table, when supported.
    fn objc_selector_table(&self) -> Option<u64> {
        None
    }

    /// Requires every original exact alias to satisfy the supplied identity check.
    fn symbols_match(&self, address: u64, matches: fn(&str) -> bool) -> bool {
        self.symbol_name(address).is_some_and(matches)
    }
}

/// One image's file-backed sections plus bounded access to external metadata targets.
/// Reads use absolute VM addresses; section provenance and final records use image-relative offsets.
struct Image<'data, 'work> {
    data: &'data [u8],
    base: u64,
    sections: Vec<(Arc<MachODataSection>, u32)>,
    selector_pool: Option<Arc<MachODataSection>>,
    context: Option<&'data dyn AddressSpace>,
    limits: BuildLimits,
    storage: &'work mut StorageBudget,
    records: &'work mut Vec<Record<'data>>,
    fixups: fixups::Fixups<'data>,
    work: u64,
    name_bytes: Cell<u64>,
    failure: Cell<Option<Reason>>,
}

impl<'data> Image<'data, '_> {
    /// Prove ownership by exactly one section before attaching provenance to an emitted address.
    fn section(&self, address: u64, size: usize) -> Option<Arc<MachODataSection>> {
        let relative = address.checked_sub(self.base)?;
        let mut matches = self.sections.iter().filter(|(section, _)| {
            relative >= section.address
                && relative
                    .checked_add(size as u64)
                    .is_some_and(|end| end <= section.address.saturating_add(section.size))
        });
        let section = matches.next()?.0.clone();
        matches.next().is_none().then_some(section)
    }

    /// Translate VM -> section-relative -> file offset, preferring this image's actual bytes.
    /// Cache fallback handles pooled names and runtime objects outside the extracted Mach-O slice.
    fn read(&self, address: u64, size: usize) -> Option<&'data [u8]> {
        let relative = address.checked_sub(self.base);
        if let Some(relative) = relative {
            for (section, offset) in &self.sections {
                let Some(delta) = relative.checked_sub(section.address) else {
                    continue;
                };
                if delta.checked_add(size as u64)? <= section.size {
                    let start = usize::try_from(u64::from(*offset).checked_add(delta)?).ok()?;
                    if let Some(bytes) = self.data.get(start..start.checked_add(size)?) {
                        return Some(bytes);
                    }
                }
            }
        }
        self.context?
            .read(address, size)
            .filter(|bytes| bytes.len() == size)
    }

    fn u32(&self, address: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.read(address, 4)?.try_into().ok()?))
    }

    /// Decode a pointer slot before dereferencing it. Imports have names but no known local target;
    /// ordinary 64-bit words are used only when no chained fixup owns the slot.
    fn pointer(&self, address: u64) -> Option<u64> {
        if let Some(pointer) = self.fixups.get(address) {
            return match pointer {
                fixups::Pointer::Address(address) => Some(*address),
                fixups::Pointer::Import { .. } => None,
            };
        }
        Some(u64::from_le_bytes(self.read(address, 8)?.try_into().ok()?))
    }

    /// Read a bounded UTF-8 C string, charging every examined byte including the terminator.
    /// Remember a budget failure even when an ABI reader treats `None` as an invalid candidate.
    fn name(&self, address: u64) -> Option<&'data str> {
        let bound = self.limits.name_length.min(4096);
        for size in 1..=bound {
            let examined = self.name_bytes.get().checked_add(1)?;
            if examined > self.limits.examined_name_bytes {
                self.failure.set(Some(Reason::ExaminedNameBytesLimit));
                return None;
            }
            self.name_bytes.set(examined);
            if self.read(address.checked_add(size as u64 - 1)?, 1)? == [0] {
                let value = std::str::from_utf8(self.read(address, size - 1)?).ok()?;
                return (!value.is_empty() && !value.chars().any(char::is_control))
                    .then_some(value);
            }
        }
        self.failure.set(Some(Reason::NameLengthLimit));
        None
    }

    /// Literal decoders share the same work budget as raw symbols, import names, and C strings.
    fn charge_name_bytes(&self, size: usize) -> Result<(), Reason> {
        let examined = self
            .name_bytes
            .get()
            .checked_add(size as u64)
            .filter(|examined| *examined <= self.limits.examined_name_bytes)
            .ok_or(Reason::ExaminedNameBytesLimit)?;
        self.name_bytes.set(examined);
        Ok(())
    }

    /// Bound graph work separately from output size: repeated or rejected candidates still cost work.
    fn step(&mut self) -> Result<(), Reason> {
        if let Some(reason) = self.failure.get() {
            return Err(reason);
        }
        self.work = self.work.checked_add(1).ok_or(Reason::RawSymbolLimit)?;
        if self.work > self.limits.raw_symbols {
            return Err(Reason::RawSymbolLimit);
        }
        Ok(())
    }

    /// Emit one exact artifact/field address, never a range or a target owned by another image.
    /// Field labels decorate the owner name without changing the address or record category.
    fn add(
        &mut self,
        address: u64,
        kind: RecordKind,
        name: &str,
        field: Option<&str>,
    ) -> Result<(), Reason> {
        self.step()?;
        let section = self.section(address, 1).or_else(|| {
            (kind == RecordKind::Selector)
                .then(|| self.selector_pool.clone())
                .flatten()
                .filter(|section| {
                    address
                        .checked_sub(self.base + section.address)
                        .is_some_and(|delta| delta < section.size)
                })
        });
        let Some(section) = section else {
            return Ok(());
        };
        if self.records.len() as u64 >= self.limits.records {
            return Err(Reason::RecordLimit);
        }
        let length = name
            .len()
            .saturating_add(field.map_or(0, |field| field.len() + 3));
        if length > self.limits.name_length {
            return Err(Reason::NameLengthLimit);
        }
        self.storage.charge(length)?;
        if self.records.len() == self.records.capacity() {
            let capacity = self.records.capacity().saturating_mul(2).max(16);
            self.storage.charge(
                capacity
                    .checked_mul(size_of::<Record<'_>>())
                    .ok_or(Reason::BuilderMemoryLimit)?,
            )?;
            self.records
                .try_reserve_exact(capacity - self.records.len())
                .map_err(|_| Reason::BuilderMemoryLimit)?;
        }
        let name = match field {
            Some(field) => format!("{name} / {field}"),
            None => name.to_owned(),
        };
        self.records.push(Record {
            name: Cow::Owned(name),
            address: address - self.base,
            section,
            kind,
        });
        Ok(())
    }

    /// Accept only complete, bounded arrays in known ABI root sections; do not salvage partial tails.
    fn roots(&self, names: &[&str], width: u64) -> Vec<(u64, u64)> {
        self.sections
            .iter()
            .filter_map(|(section, _)| {
                (names.contains(&section.name.as_str())
                    && section.size % width == 0
                    && section.size / width <= 100_000)
                    .then_some((self.base + section.address, section.size / width))
            })
            .collect()
    }
}

/// Append derived descriptions after raw symbol collection, carrying its examined-name budget forward.
/// Unsupported pointer encodings leave raw symbols intact rather than interpreting packed bits as VAs.
pub(crate) fn extract<'data>(
    object: &MachObject<'data>,
    context: Option<&'data dyn AddressSpace>,
    limits: BuildLimits,
    storage: &mut StorageBudget,
    records: &mut Vec<Record<'data>>,
    examined_name_bytes: u64,
) -> Result<(), Reason> {
    let macho = MachO::parse(object.data(), 0).map_err(|_| Reason::SourceError)?;
    if !macho.is_64 || !macho.little_endian {
        return Ok(());
    }
    let Some(fixups) = fixups::Fixups::parse(
        &macho,
        object.data(),
        object.load_address(),
        BuildLimits {
            examined_name_bytes: limits
                .examined_name_bytes
                .saturating_sub(examined_name_bytes),
            ..limits
        },
        storage,
    )?
    else {
        tracing::debug!("skipping runtime metadata with unsupported chained-pointer encoding");
        return Ok(());
    };
    let examined_name_bytes = examined_name_bytes
        .checked_add(fixups.examined_name_bytes)
        .ok_or(Reason::ExaminedNameBytesLimit)?;
    let mut image = Image {
        data: object.data(),
        base: object.load_address(),
        sections: Vec::new(),
        selector_pool: None,
        context,
        limits,
        storage,
        records,
        fixups,
        work: 0,
        name_bytes: Cell::new(examined_name_bytes),
        failure: Cell::new(None),
    };
    let mut ordinal = 0;
    for segment in &macho.segments {
        if segment.name().ok() == Some("__OBJC_RO") {
            let address = segment
                .vmaddr
                .checked_sub(image.base)
                .ok_or(Reason::SourceError)?;
            if image.selector_pool.is_some() || segment.vmaddr.checked_add(segment.vmsize).is_none()
            {
                return Err(Reason::SourceError);
            }
            image.selector_pool = Some(Arc::new(MachODataSection {
                index: 0,
                segment_name: "__OBJC_RO".to_owned(),
                name: "__selectors".to_owned(),
                address,
                size: segment.vmsize,
                flags: 0,
            }));
        }
        for section in segment {
            let (section, _) = section.map_err(|_| Reason::SourceError)?;
            // Mach-O n_sect is a 1-based ordinal across every segment, including sections we skip.
            // S_ZEROFILL, S_GB_ZEROFILL, and S_THREAD_LOCAL_ZEROFILL have no bytes to parse on disk.
            ordinal += 1;
            if ordinal > 255 {
                return Err(Reason::SourceError);
            }
            if matches!(section.flags & 0xff, 1 | 0xc | 0x12) {
                continue;
            }
            let Some(address) = section.addr.checked_sub(image.base) else {
                return Ok(());
            };
            image.sections.push((
                Arc::new(MachODataSection {
                    index: ordinal as u8,
                    segment_name: section
                        .segname()
                        .map_err(|_| Reason::SourceError)?
                        .to_owned(),
                    name: section.name().map_err(|_| Reason::SourceError)?.to_owned(),
                    address,
                    size: section.size,
                    flags: section.flags,
                }),
                section.offset,
            ));
        }
    }
    // Each reader validates its own root/structure ABI. A sticky string-budget failure must still
    // escape even if the last reader merely skipped the candidate that exhausted that budget.
    image.objc()?;
    image.swift()?;
    image.constant_strings()?;
    image.constant_objects()?;
    image.selectors()?;
    match image.failure.get() {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}
