use std::ops::Range;
use std::str;

use symbolic_common::Arch;

use crate::format::{digest, read_u32, read_u64, tables, Table, HEADER_SIZE, MAGIC, VERSION};
use crate::{Identity, ObjectKind, ParseError, ReadLimits, Reason, State, Statistics};

mod validation;

/// A fully validated borrowed cache. Keep its immutable backing bytes alive for all views.
#[derive(Debug)]
pub struct DataCache<'data> {
    identity: Identity,
    state: State,
    reason: Reason,
    statistics: Statistics,
    addresses: Table<'data>,
    records: Table<'data>,
    sections: Table<'data>,
    strings: &'data str,
}

/// Borrowed provenance for a section; bounds do not imply a symbol's size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataSection<'data> {
    /// Inclusive image-relative start.
    pub address: u64,
    /// In-memory extent.
    pub size: u64,
    /// Original one-based Mach-O ordinal.
    pub macho_ordinal: u32,
    /// Original section flags.
    pub flags: u32,
    /// Original segment spelling.
    pub segment_name: &'data str,
    /// Original section spelling.
    pub name: &'data str,
}

/// An exact-match raw symbol view, not an inferred allocation type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataSymbol<'data> {
    /// Matched image-relative address.
    pub address: u64,
    /// Raw symbol spelling, including leading underscores.
    pub name: &'data str,
    /// Original section provenance.
    pub section: DataSection<'data>,
}

impl<'data> DataCache<'data> {
    /// Validates uncompressed bytes once, without an expanded address map or string copies.
    /// Unaligned slices are supported; integers are decoded explicitly as little-endian bytes.
    pub fn parse(bytes: &'data [u8], limits: ReadLimits) -> Result<Self, ParseError> {
        if bytes.len() as u64 > limits.file_bytes {
            return Err(ParseError::Limit("file bytes"));
        }
        if bytes.len() < HEADER_SIZE || &bytes[..8] != MAGIC {
            return Err(ParseError::Header);
        }
        if read_u32(bytes, 8) != VERSION {
            return Err(ParseError::Version(read_u32(bytes, 8)));
        }
        if read_u32(bytes, 12) != HEADER_SIZE as u32
            || bytes[216..256].iter().any(|byte| *byte != 0)
        {
            return Err(ParseError::Header);
        }
        if read_u64(bytes, 16) != bytes.len() as u64 {
            return Err(ParseError::Bounds);
        }
        let arch_code = read_u32(bytes, 48);
        let arch = Arch::from_u32(arch_code);
        if arch as u32 != arch_code {
            return Err(ParseError::Enum("architecture"));
        }
        let object_kind = match read_u32(bytes, 52) {
            1 => ObjectKind::Debug,
            2 => ObjectKind::Executable,
            3 => ObjectKind::Library,
            _ => return Err(ParseError::Enum("object kind")),
        };
        let state = match read_u32(bytes, 56) {
            0 => State::Complete,
            1 => State::Incomplete,
            2 => State::Unsupported,
            _ => return Err(ParseError::Enum("state")),
        };
        let reason = match read_u32(bytes, 60) {
            0 => Reason::None,
            1 => Reason::UnsupportedArchitecture,
            2 => Reason::SourceError,
            3 => Reason::RawSymbolLimit,
            4 => Reason::RecordLimit,
            5 => Reason::AliasLimit,
            6 => Reason::NameLengthLimit,
            7 => Reason::ExaminedNameBytesLimit,
            8 => Reason::StringPoolLimit,
            9 => Reason::FileSizeLimit,
            10 => Reason::BuilderMemoryLimit,
            _ => return Err(ParseError::Enum("reason")),
        };
        let valid_state = match state {
            State::Complete => reason == Reason::None && arch != Arch::Unknown,
            State::Incomplete => !matches!(reason, Reason::None | Reason::UnsupportedArchitecture),
            State::Unsupported => reason == Reason::UnsupportedArchitecture,
        };
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&bytes[24..40]);
        let statistics = Statistics {
            declared_symbols: read_u64(bytes, 192),
            inspected_symbols: read_u64(bytes, 200),
            accepted_records: read_u64(bytes, 208),
        };
        if !valid_state
            || uuid == [0; 16]
            || statistics.inspected_symbols > statistics.declared_symbols
            || statistics.accepted_records > statistics.inspected_symbols
            || (state == State::Complete
                && statistics.inspected_symbols != statistics.declared_symbols)
        {
            return Err(ParseError::Identity);
        }
        let [addresses, records, sections, strings] = tables(
            bytes,
            [
                limits.addresses,
                limits.records,
                limits.sections.min(255),
                limits.string_bytes,
            ],
        )?;
        if bytes[96..128] != digest(&bytes[HEADER_SIZE..]) {
            return Err(ParseError::Checksum);
        }
        let strings = str::from_utf8(strings.bytes).map_err(|_| ParseError::Utf8)?;
        let mut source_digest = [0; 32];
        source_digest.copy_from_slice(&bytes[64..96]);
        let cache = Self {
            identity: Identity {
                uuid,
                preferred_load_address: read_u64(bytes, 40),
                arch,
                object_kind,
                source_digest,
            },
            state,
            reason,
            statistics,
            addresses,
            records,
            sections,
            strings,
        };
        if (state != State::Complete || addresses.len() == 0)
            && (records.len() != 0
                || sections.len() != 0
                || !strings.is_empty()
                || addresses.len() != 0)
        {
            return Err(ParseError::Layout);
        }
        cache.validate(limits)?;
        Ok(cache)
    }

    /// Original object identity and source digest.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Completeness of the original extraction.
    pub fn state(&self) -> State {
        self.state
    }
    /// Terminal reason, or [`Reason::None`] for complete extraction.
    pub fn reason(&self) -> Reason {
        self.reason
    }
    /// Bounded extraction counters.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Number of distinct searchable addresses.
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }
    /// Number of searchable raw aliases after exact duplicate removal.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn string(&self, row: &[u8], offset: usize) -> Result<&'data str, ParseError> {
        let start = read_u32(row, offset) as usize;
        let end = start
            .checked_add(read_u32(row, offset + 4) as usize)
            .ok_or(ParseError::Bounds)?;
        self.strings.get(start..end).ok_or(ParseError::Utf8)
    }

    fn section(&self, index: usize) -> Result<DataSection<'data>, ParseError> {
        if index >= self.sections.len() {
            return Err(ParseError::Reference);
        }
        let row = self.sections.row(index);
        Ok(DataSection {
            address: read_u64(row, 0),
            size: read_u64(row, 8),
            macho_ordinal: read_u32(row, 16),
            flags: read_u32(row, 20),
            segment_name: self.string(row, 24)?,
            name: self.string(row, 32)?,
        })
    }

    fn find(&self, address: u64, mut compared: impl FnMut()) -> Range<usize> {
        let mut low = 0;
        let mut high = self.addresses.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let row = self.addresses.row(middle);
            compared();
            match read_u64(row, 0).cmp(&address) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => {
                    let first = read_u32(row, 8) as usize;
                    return first..first + read_u32(row, 12) as usize;
                }
            }
        }
        0..0
    }

    /// Returns all raw aliases at exactly this image-relative address in `O(log N + K)` work.
    pub fn lookup_exact(&self, address: u64) -> Matches<'_, 'data> {
        Matches {
            cache: self,
            address,
            records: self.find(address, || {}),
        }
    }

    #[cfg(test)]
    pub(crate) fn comparison_count(&self, address: u64) -> usize {
        let mut comparisons = 0;
        self.find(address, || comparisons += 1);
        comparisons
    }
}

/// Allocation-free exact-address aliases, borrowing a validated cache and its backing bytes.
pub struct Matches<'cache, 'data> {
    cache: &'cache DataCache<'data>,
    address: u64,
    records: Range<usize>,
}

impl<'data> Iterator for Matches<'_, 'data> {
    type Item = DataSymbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let row = self.cache.records.row(self.records.next()?);
        Some(DataSymbol {
            address: self.address,
            name: self.cache.string(row, 4).ok()?,
            section: self.cache.section(read_u32(row, 0) as usize).ok()?,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.records.size_hint()
    }
}

impl ExactSizeIterator for Matches<'_, '_> {}
impl std::iter::FusedIterator for Matches<'_, '_> {}
