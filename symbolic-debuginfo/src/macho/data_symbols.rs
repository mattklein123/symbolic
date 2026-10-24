use std::sync::Arc;

use goblin::container::{Container, Ctx};
use goblin::mach::{constants, load_command, symbols};
use scroll::{Endian, Pread};
use symbolic_common::Arch;

use super::{MachError, MachObject};

#[cfg(test)]
#[path = "data_symbols_test.rs"]
mod tests;

/// The section containing a Mach-O data symbol. Addresses are relative to the image load address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachODataSection {
    /// One-based Mach-O section ordinal, including sections not exposed by this API.
    pub index: u8,
    /// Name of the containing segment.
    pub segment_name: String,
    /// Name of the section.
    pub name: String,
    /// Inclusive section start relative to [`MachObject::load_address`].
    pub address: u64,
    /// Section extent in memory, not the number of bytes stored in the file.
    pub size: u64,
    /// Unmodified Mach-O section type and attributes.
    pub flags: u32,
}

/// A section-defined, non-code Mach-O symbol, without inferred type identity or symbol size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachODataSymbol<'data> {
    /// Exact symbol-table spelling, including leading underscores and hidden bitcode names.
    pub name: &'data str,
    /// Address relative to [`MachObject::load_address`].
    pub address: u64,
    /// Validated section metadata, shared between symbols in the same section.
    pub section: Arc<MachODataSection>,
    /// Architecture of the owning Mach-O slice.
    pub arch: Arch,
}

/// An iterator over data-symbol records in original symbol-table order.
///
/// Aliases are retained. Parsing errors are returned rather than silently truncating extraction.
pub struct MachODataSymbolIterator<'data> {
    symbols: symbols::SymbolIterator<'data>,
    sections: Vec<Option<Arc<MachODataSection>>>,
    load_address: u64,
    arch: Arch,
    string_table_size: usize,
}

impl<'data> MachObject<'data> {
    /// Returns section-defined data symbols without changing the code-only [`Self::symbols`] API.
    ///
    /// Includes non-instruction sections of `__TEXT`, `__DATA*`, `__AUTH*`, and `__OBJC`.
    /// Debug sections, instructions, stubs, undefined symbols, and absolute symbols are excluded.
    /// Section bytes need not exist in the file, as is common for dSYM debug companions.
    /// Names are raw: no underscore stripping, bitcode resolution, or type recognition is applied.
    /// Section ranges are half-open; no symbol size or nearest-preceding association is inferred.
    /// Sectionless, empty-name, and out-of-range symbols are skipped.
    ///
    /// Malformed section headers or ranges and unrepresentable section ordinals return an error
    /// before iteration. Malformed symbol records or string-table bounds yield iterator errors.
    pub fn data_symbols(&self) -> Result<MachODataSymbolIterator<'data>, MachError> {
        let load_address = self.load_address();
        let mut sections = Vec::new();
        for segment in &self.macho.segments {
            let section_count = sections
                .len()
                .checked_add(segment.nsects as usize)
                .filter(|count| *count <= u8::MAX as usize)
                .ok_or_else(|| MachError::new("too many Mach-O sections for a symbol ordinal"))?;
            let (command_size, section_size) = if self.macho.is_64 {
                (
                    load_command::SIZEOF_SEGMENT_COMMAND_64,
                    load_command::SIZEOF_SECTION_64,
                )
            } else {
                (
                    load_command::SIZEOF_SEGMENT_COMMAND_32,
                    load_command::SIZEOF_SECTION_32,
                )
            };
            if (segment.cmdsize as usize) < command_size + segment.nsects as usize * section_size {
                return Err(MachError::new(
                    "Mach-O section headers exceed segment command",
                ));
            }
            let segment_name = segment.name()?;
            if segment_name != "__TEXT"
                && !segment_name.starts_with("__DATA")
                && !segment_name.starts_with("__AUTH")
                && segment_name != "__OBJC"
            {
                sections.resize_with(section_count, || None);
                continue;
            }
            let segment_end = segment
                .vmaddr
                .checked_add(segment.vmsize)
                .ok_or_else(|| MachError::new("Mach-O segment address overflow"))?;
            for result in segment {
                let (section, _) = result?;
                let index = (sections.len() + 1) as u8;
                let name = section.name()?;
                let is_code = section.flags
                    & (constants::S_ATTR_PURE_INSTRUCTIONS
                        | constants::S_ATTR_SOME_INSTRUCTIONS
                        | constants::S_ATTR_DEBUG)
                    != 0
                    || section.flags & constants::SECTION_TYPE == constants::S_SYMBOL_STUBS
                    || matches!(name, "__text" | "__stubs" | "__stub_helper");
                if is_code || section.size == 0 {
                    sections.push(None);
                    continue;
                }
                let end = section
                    .addr
                    .checked_add(section.size)
                    .ok_or_else(|| MachError::new("Mach-O section address overflow"))?;
                if section.segname()? != segment_name
                    || section.addr < segment.vmaddr
                    || end > segment_end
                {
                    return Err(MachError::new(
                        "Mach-O data section lies outside its segment",
                    ));
                }
                let address = section
                    .addr
                    .checked_sub(load_address)
                    .ok_or_else(|| MachError::new("Mach-O data section precedes image base"))?;
                sections.push(Some(Arc::new(MachODataSection {
                    index,
                    segment_name: segment_name.to_owned(),
                    name: name.to_owned(),
                    address,
                    size: section.size,
                    flags: section.flags,
                })));
            }
        }
        Ok(MachODataSymbolIterator {
            symbols: self.macho.symbols(),
            sections,
            load_address,
            arch: self.arch(),
            string_table_size: self
                .macho
                .load_commands
                .iter()
                .find_map(|command| match &command.command {
                    load_command::CommandVariant::Symtab(table) => Some(table.strsize as usize),
                    _ => None,
                })
                .unwrap_or(0),
        })
    }
}

impl<'data> Iterator for MachODataSymbolIterator<'data> {
    type Item = Result<MachODataSymbol<'data>, MachError>;

    fn next(&mut self) -> Option<Self::Item> {
        for result in &mut self.symbols {
            let (name, symbol) = match result {
                Ok(symbol) => symbol,
                Err(error) => return Some(Err(error.into())),
            };
            if !symbol
                .n_strx
                .checked_add(name.len())
                .is_some_and(|end| end < self.string_table_size)
            {
                return Some(Err(MachError::new(
                    "Mach-O symbol name exceeds string table",
                )));
            }
            if symbol.is_stab() || symbol.get_type() != symbols::N_SECT || name.is_empty() {
                continue;
            }
            let Some(section) = symbol
                .n_sect
                .checked_sub(1)
                .and_then(|index| self.sections.get(index))
                .and_then(Option::as_ref)
            else {
                continue;
            };
            let Some(address) = symbol.n_value.checked_sub(self.load_address) else {
                continue;
            };
            if address < section.address || address - section.address >= section.size {
                continue;
            }
            return Some(Ok(MachODataSymbol {
                name,
                address,
                section: Arc::clone(section),
                arch: self.arch,
            }));
        }
        None
    }
}

/// Work limits for bounded extraction, including entries excluded from data-symbol output.
#[derive(Clone, Copy, Debug)]
pub struct DataSymbolLimits {
    /// Maximum raw nlist entries to inspect.
    pub raw_symbols: u64,
    /// Maximum bytes in any raw symbol name, excluding its terminator.
    pub name_length: usize,
    /// Maximum cumulative name bytes examined, including repeated and excluded names.
    pub name_bytes: u64,
}

/// A bounded extraction failure. No further records follow an error.
#[derive(Debug, thiserror::Error)]
pub enum DataSymbolError {
    /// Malformed source metadata or symbol bytes.
    #[error(transparent)]
    Source(#[from] MachError),
    /// Too many raw entries, even if they would all be excluded.
    #[error("raw symbol limit exceeded")]
    RawSymbolLimit,
    /// A raw name exceeds the per-name limit.
    #[error("symbol name length limit exceeded")]
    NameLengthLimit,
    /// Cumulative examined name bytes exceed the limit.
    #[error("examined symbol name bytes limit exceeded")]
    NameBytesLimit,
}

/// Bounded counterpart to [`MachODataSymbolIterator`], borrowing the original nlist/string tables.
pub struct BoundedMachODataSymbols<'data> {
    symbols: &'data [u8],
    strings: &'data [u8],
    sections: Vec<Option<Arc<MachODataSection>>>,
    context: Ctx,
    entry_size: usize,
    load_address: u64,
    arch: Arch,
    declared: u64,
    inspected: u64,
    examined: u64,
    limits: DataSymbolLimits,
    finished: bool,
}

impl<'data> MachObject<'data> {
    /// Extracts raw data symbols with bounded entry and name work before UTF-8 decoding.
    ///
    /// Unlike the unbounded iterator, an error terminates extraction. Names of excluded records
    /// also consume budget; NUL terminators are covered by the raw-entry bound.
    pub fn bounded_data_symbols(
        &self,
        limits: DataSymbolLimits,
    ) -> Result<BoundedMachODataSymbols<'data>, MachError> {
        let metadata = self.data_symbols()?;
        let table = self.macho.load_commands.iter().find_map(|command| {
            if let load_command::CommandVariant::Symtab(table) = &command.command {
                Some(table)
            } else {
                None
            }
        });
        let entry_size = if self.macho.is_64 {
            symbols::SIZEOF_NLIST_64
        } else {
            symbols::SIZEOF_NLIST_32
        };
        let (raw_symbols, strings, declared) = if let Some(table) = table {
            let start = table.symoff as usize;
            let end = (table.nsyms as usize)
                .checked_mul(entry_size)
                .and_then(|size| start.checked_add(size))
                .ok_or_else(|| MachError::new("Mach-O symbol table extent overflow"))?;
            let string_start = table.stroff as usize;
            let string_end = string_start
                .checked_add(table.strsize as usize)
                .ok_or_else(|| MachError::new("Mach-O string table extent overflow"))?;
            (
                self.data
                    .get(start..end)
                    .ok_or_else(|| MachError::new("Mach-O symbol table exceeds source"))?,
                self.data
                    .get(string_start..string_end)
                    .ok_or_else(|| MachError::new("Mach-O string table exceeds source"))?,
                u64::from(table.nsyms),
            )
        } else {
            (&[][..], &[][..], 0)
        };
        Ok(BoundedMachODataSymbols {
            symbols: raw_symbols,
            strings,
            sections: metadata.sections,
            context: Ctx::new(
                if self.macho.is_64 {
                    Container::Big
                } else {
                    Container::Little
                },
                if self.macho.little_endian {
                    Endian::Little
                } else {
                    Endian::Big
                },
            ),
            entry_size,
            load_address: metadata.load_address,
            arch: metadata.arch,
            declared,
            inspected: 0,
            examined: 0,
            limits,
            finished: false,
        })
    }
}

impl<'data> BoundedMachODataSymbols<'data> {
    /// Declared raw nlist entries, including excluded entries.
    pub fn declared_symbols(&self) -> u64 {
        self.declared
    }

    /// Number of entries inspected so far.
    pub fn inspected_symbols(&self) -> u64 {
        self.inspected
    }

    /// Cumulative raw name bytes examined so far.
    pub fn examined_name_bytes(&self) -> u64 {
        self.examined
    }

    fn next_record(&mut self) -> Result<Option<MachODataSymbol<'data>>, DataSymbolError> {
        while self.inspected < self.declared {
            if self.inspected >= self.limits.raw_symbols {
                return Err(DataSymbolError::RawSymbolLimit);
            }
            let offset = self.inspected as usize * self.entry_size;
            self.inspected += 1;
            let symbol: symbols::Nlist = self
                .symbols
                .pread_with(offset, self.context)
                .map_err(MachError::from)?;
            let tail = self
                .strings
                .get(symbol.n_strx..)
                .ok_or_else(|| MachError::new("Mach-O symbol name exceeds string table"))?;
            let remaining = self.limits.name_bytes.saturating_sub(self.examined);
            let scan = tail
                .len()
                .min(self.limits.name_length.saturating_add(1))
                .min(
                    usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .saturating_add(1),
                );
            let length = tail[..scan].iter().position(|byte| *byte == 0);
            let Some(length) = length else {
                self.examined += (scan as u64).min(remaining);
                return Err(
                    if remaining <= self.limits.name_length as u64 && remaining < tail.len() as u64
                    {
                        DataSymbolError::NameBytesLimit
                    } else if scan > self.limits.name_length {
                        DataSymbolError::NameLengthLimit
                    } else {
                        MachError::new("unterminated Mach-O symbol name").into()
                    },
                );
            };
            self.examined += length as u64;
            let name = std::str::from_utf8(&tail[..length])
                .map_err(|_| MachError::new("invalid UTF-8 Mach-O symbol name"))?;
            if symbol.is_stab() || symbol.get_type() != symbols::N_SECT || name.is_empty() {
                continue;
            }
            let Some(section) = symbol
                .n_sect
                .checked_sub(1)
                .and_then(|index| self.sections.get(index))
                .and_then(Option::as_ref)
            else {
                continue;
            };
            let Some(address) = symbol.n_value.checked_sub(self.load_address) else {
                continue;
            };
            if address < section.address || address - section.address >= section.size {
                continue;
            }
            return Ok(Some(MachODataSymbol {
                name,
                address,
                section: Arc::clone(section),
                arch: self.arch,
            }));
        }
        Ok(None)
    }
}

impl<'data> Iterator for BoundedMachODataSymbols<'data> {
    type Item = Result<MachODataSymbol<'data>, DataSymbolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            result => {
                self.finished = true;
                result.err().map(Err)
            }
        }
    }
}
