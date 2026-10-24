use symbolic_common::Arch;

/// Identity and provenance of one original Mach-O slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Original UUID bytes in Mach-O order, never Windows GUID order.
    pub uuid: [u8; 16],
    /// Original preferred image load address; cached addresses are already relative to it.
    pub preferred_load_address: u64,
    /// Original architecture.
    pub arch: Arch,
    /// Kind of the original object.
    pub object_kind: ObjectKind,
    /// SHA-256 of the original Mach-O slice, supplied by the ingestion caller.
    pub source_digest: [u8; 32],
}

/// Object kinds supported by format version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ObjectKind {
    /// A debug companion, such as a dSYM slice.
    Debug = 1,
    /// An executable slice.
    Executable = 2,
    /// A shared-library slice.
    Library = 3,
}

/// Completeness of extraction. Only complete files contain searchable records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum State {
    /// All raw symbols were inspected successfully, possibly yielding no data symbols.
    Complete = 0,
    /// Extraction stopped; no partial alias groups are exposed.
    Incomplete = 1,
    /// The source architecture is unsupported.
    Unsupported = 2,
}

/// Bounded diagnostic reason, with stable format-v1 wire discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Reason {
    /// Complete extraction.
    None = 0,
    /// Unknown architecture.
    UnsupportedArchitecture = 1,
    /// Malformed source metadata or symbol bytes.
    SourceError = 2,
    /// Raw-entry budget exhausted.
    RawSymbolLimit = 3,
    /// Accepted-record budget exhausted.
    RecordLimit = 4,
    /// Too many aliases at one address.
    AliasLimit = 5,
    /// A raw name is too long.
    NameLengthLimit = 6,
    /// Cumulative examined name work exceeded its budget.
    ExaminedNameBytesLimit = 7,
    /// Interned string pool is too large.
    StringPoolLimit = 8,
    /// Uncompressed file would be too large.
    FileSizeLimit = 9,
    /// Accounted builder-owned storage exceeded its budget.
    BuilderMemoryLimit = 10,
}

/// Extraction counters. Accepted records are counted before duplicate removal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Number of declared raw nlist entries.
    pub declared_symbols: u64,
    /// Number of raw entries inspected, including excluded entries.
    pub inspected_symbols: u64,
    /// Number of accepted raw records, including exact duplicates.
    pub accepted_records: u64,
}

/// Independent bounds on untrusted data-cache files, enforced before table traversal.
#[derive(Clone, Copy, Debug)]
pub struct ReadLimits {
    /// Maximum uncompressed file bytes.
    pub file_bytes: u64,
    /// Maximum distinct address entries.
    pub addresses: u64,
    /// Maximum symbol records.
    pub records: u64,
    /// Maximum section rows.
    pub sections: u64,
    /// Maximum interned string bytes.
    pub string_bytes: u64,
    /// Maximum aliases at one address.
    pub aliases: u64,
    /// Maximum raw symbol name bytes.
    pub name_length: u64,
    /// Maximum cumulative referenced symbol-name bytes.
    pub referenced_name_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            file_bytes: 64 << 20,
            addresses: 1_000_000,
            records: 1_000_000,
            sections: 255,
            string_bytes: 32 << 20,
            aliases: 4096,
            name_length: 16 << 10,
            referenced_name_bytes: 64 << 20,
        }
    }
}

/// Construction budgets; callers may lower these independently of reader limits.
#[derive(Clone, Copy, Debug)]
pub struct BuildLimits {
    /// Maximum inspected nlist entries, including filtered entries.
    pub raw_symbols: u64,
    /// Maximum accepted raw records, before duplicate removal.
    pub records: u64,
    /// Maximum accepted aliases at one address, before duplicate removal.
    pub aliases: u64,
    /// Maximum individual raw symbol name bytes.
    pub name_length: usize,
    /// Maximum cumulative examined name bytes, before interning.
    pub examined_name_bytes: u64,
    /// Maximum interned string bytes.
    pub string_bytes: u64,
    /// Maximum serialized file bytes (including terminal headers).
    pub file_bytes: u64,
    /// Maximum accounted builder-owned storage, not allocator RSS or caller-owned source bytes.
    pub memory_bytes: u64,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            raw_symbols: 2_000_000,
            records: 1_000_000,
            aliases: 4096,
            name_length: 16 << 10,
            examined_name_bytes: 64 << 20,
            string_bytes: 32 << 20,
            file_bytes: 64 << 20,
            memory_bytes: 256 << 20,
        }
    }
}

/// A malformed, unsupported, or over-budget cache. No malformed prefix is salvaged.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ParseError {
    /// Invalid magic, header length, or reserved header bytes.
    #[error("invalid data-cache header")]
    Header,
    /// This reader does not support the given format version.
    #[error("unsupported data-cache version {0}")]
    Version(u32),
    /// An unknown architecture, object kind, state, or reason code.
    #[error("invalid data-cache enum: {0}")]
    Enum(&'static str),
    /// Invalid UUID, state/reason combination, or extraction counters.
    #[error("invalid data-cache identity or state")]
    Identity,
    /// A configured resource limit was exceeded.
    #[error("data-cache limit exceeded: {0}")]
    Limit(&'static str),
    /// Overflow or an out-of-file table/string reference.
    #[error("invalid data-cache bounds")]
    Bounds,
    /// Noncanonical table extents, alignment, padding, or trailing bytes.
    #[error("invalid data-cache layout")]
    Layout,
    /// Digest mismatch.
    #[error("data-cache payload checksum mismatch")]
    Checksum,
    /// Invalid row/string reference, section extent, or address membership.
    #[error("invalid data-cache record reference")]
    Reference,
    /// Unsorted/duplicate addresses, sections, or aliases, or noncontiguous record groups.
    #[error("invalid data-cache table ordering")]
    Ordering,
    /// Invalid UTF-8 string pool or string boundary.
    #[error("invalid data-cache UTF-8")]
    Utf8,
}
