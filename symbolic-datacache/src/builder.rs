//! Build a self-contained exact-address index in two stages: raw section-defined symbols, then
//! rooted runtime metadata. Both stages share budgets and source identity. Serialization is all or
//! nothing: a failed stage produces a terminal header, never searchable partial results.

use std::borrow::Cow;
use std::io::{self, Write};
use std::mem::size_of;
use std::sync::Arc;

use symbolic_common::Arch;
use symbolic_debuginfo::macho::{DataSymbolError, DataSymbolLimits, MachODataSection, MachObject};
use symbolic_debuginfo::ObjectKind as SourceKind;

use crate::format::{digest, write_u32, write_u64, HEADER_SIZE, MAGIC, VERSION};
use crate::writer::encode;
use crate::AddressSpace;
use crate::{BuildLimits, Identity, ObjectKind, Reason, RecordKind, State, Statistics};

/// Internal canonicalization input: raw names borrow the object, derived descriptions own labels.
/// Addresses are image-relative; the shared section preserves the original Mach-O ordinal/flags.
pub(crate) struct Record<'data> {
    pub name: Cow<'data, str>,
    pub address: u64,
    pub section: Arc<MachODataSection>,
    pub kind: RecordKind,
}

//
// DataCacheBuilder
//

/// A canonical, uncompressed cache built once during ingestion.
///
/// Temporary storage is released before this value is returned. A terminal incomplete or
/// unsupported result contains only its identity, counters, and reason, never a partial table.
#[derive(Debug)]
pub struct DataCacheBuilder {
    bytes: Vec<u8>,
    state: State,
    reason: Reason,
    statistics: Statistics,
    accounted_storage: u64,
}

/// Configuration, identity, allocation, or output errors, distinct from terminal extraction state.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Mach-O UUID is missing or nil.
    #[error("data-cache source has no UUID")]
    MissingIdentity,
    /// The source is not a debug companion, executable, or library.
    #[error("unsupported data-cache source object kind")]
    ObjectKind,
    /// Even the fixed terminal header cannot fit the configured budgets.
    #[error("data-cache limits must permit a 256-byte terminal header")]
    InvalidLimits,
    /// The terminal header could not be allocated.
    #[error("could not allocate data-cache header")]
    Allocation,
    /// Writing the output failed; callers must discard their partial destination.
    #[error(transparent)]
    Io(#[from] io::Error),
}

//
// StorageBudget
//

/// Conservative cumulative accounting for builder-owned allocations, including capacity growth.
/// Released intermediate buffers are not credited back, so later phases cannot hide earlier costs.
pub(crate) struct StorageBudget {
    pub used: u64,
    pub limit: u64,
}

impl StorageBudget {
    pub fn charge(&mut self, bytes: usize) -> Result<(), Reason> {
        let used = self
            .used
            .checked_add(bytes as u64)
            .ok_or(Reason::BuilderMemoryLimit)?;
        if used > self.limit {
            return Err(Reason::BuilderMemoryLimit);
        }
        self.used = used;
        Ok(())
    }
}

/// Start with a valid 256-byte header whose four table ranges are empty at the end of the header.
/// The encoder fills their offsets/counts and payload digest only after canonicalization succeeds.
pub(crate) fn header(
    identity: Identity,
    state: State,
    reason: Reason,
    statistics: Statistics,
) -> Result<Vec<u8>, BuildError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(HEADER_SIZE)
        .map_err(|_| BuildError::Allocation)?;
    bytes.resize(HEADER_SIZE, 0);
    bytes[..8].copy_from_slice(MAGIC);
    write_u32(&mut bytes, 8, VERSION);
    write_u32(&mut bytes, 12, HEADER_SIZE as u32);
    write_u64(&mut bytes, 16, HEADER_SIZE as u64);
    bytes[24..40].copy_from_slice(&identity.uuid);
    write_u64(&mut bytes, 40, identity.preferred_load_address);
    write_u32(&mut bytes, 48, identity.arch as u32);
    write_u32(&mut bytes, 52, identity.object_kind as u32);
    write_u32(&mut bytes, 56, state as u32);
    write_u32(&mut bytes, 60, reason as u32);
    bytes[64..96].copy_from_slice(&identity.source_digest);
    bytes[96..128].copy_from_slice(&digest(&[]));
    for index in 0..4 {
        write_u64(&mut bytes, 128 + index * 16, HEADER_SIZE as u64);
    }
    write_u64(&mut bytes, 192, statistics.declared_symbols);
    write_u64(&mut bytes, 200, statistics.inspected_symbols);
    write_u64(&mut bytes, 208, statistics.accepted_records);
    Ok(bytes)
}

impl DataCacheBuilder {
    /// Extracts a bounded canonical cache from one Mach-O slice.
    ///
    /// `source_digest` must be SHA-256 of that original slice, not its archive or SymCache.
    /// Accounted storage includes vector capacities, intern references, output bytes, and a
    /// conservative 64-KiB allowance for at most 255 extraction sections and sorting scratch.
    /// It excludes caller-owned source bytes and allocator metadata/RSS. Raw names remain borrowed;
    /// derived metadata descriptions allocate owned labels.
    pub fn from_macho(
        object: &MachObject<'_>,
        source_digest: [u8; 32],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::from_macho_with_context(object, source_digest, limits, None)
    }

    /// Builds a self-contained index with optional ingestion-only shared-cache address context.
    ///
    /// Context bytes are used only while building; neither lookup nor the serialized index
    /// depends on retaining the context. Source identity remains that of the original slice.
    pub fn from_macho_with_context<'data>(
        object: &MachObject<'data>,
        source_digest: [u8; 32],
        limits: BuildLimits,
        context: Option<&'data dyn AddressSpace>,
    ) -> Result<Self, BuildError> {
        if limits.file_bytes < HEADER_SIZE as u64 || limits.memory_bytes < HEADER_SIZE as u64 {
            return Err(BuildError::InvalidLimits);
        }
        let uuid = *object.debug_id().uuid().as_bytes();
        if uuid == [0; 16] {
            return Err(BuildError::MissingIdentity);
        }
        let object_kind = match object.kind() {
            SourceKind::Debug => ObjectKind::Debug,
            SourceKind::Executable => ObjectKind::Executable,
            SourceKind::Library => ObjectKind::Library,
            _ => return Err(BuildError::ObjectKind),
        };
        let identity = Identity {
            uuid,
            preferred_load_address: object.load_address(),
            arch: object.arch(),
            object_kind,
            source_digest,
        };
        let mut statistics = Statistics::default();
        if identity.arch == Arch::Unknown {
            return Self::terminal(
                identity,
                Reason::UnsupportedArchitecture,
                statistics,
                HEADER_SIZE as u64,
            );
        }
        let mut storage = StorageBudget {
            used: HEADER_SIZE as u64,
            limit: limits.memory_bytes,
        };
        if storage.charge(64 << 10).is_err() {
            return Self::terminal(
                identity,
                Reason::BuilderMemoryLimit,
                statistics,
                storage.used,
            );
        }
        let mut symbols = match object.bounded_address_symbols(DataSymbolLimits {
            raw_symbols: limits.raw_symbols,
            name_length: limits.name_length,
            name_bytes: limits.examined_name_bytes,
        }) {
            Ok(symbols) => symbols,
            Err(_) => {
                return Self::terminal(identity, Reason::SourceError, statistics, storage.used)
            }
        };
        statistics.declared_symbols = symbols.declared_symbols();
        let mut records = Vec::new();
        let mut failure = None;
        for result in symbols.by_ref() {
            let record = match result {
                Ok(record) => record,
                Err(error) => {
                    failure = Some(match error {
                        DataSymbolError::Source(_) => Reason::SourceError,
                        DataSymbolError::RawSymbolLimit => Reason::RawSymbolLimit,
                        DataSymbolError::NameLengthLimit => Reason::NameLengthLimit,
                        DataSymbolError::NameBytesLimit => Reason::ExaminedNameBytesLimit,
                    });
                    break;
                }
            };
            statistics.accepted_records += 1;
            if statistics.accepted_records > limits.records {
                failure = Some(Reason::RecordLimit);
                break;
            }
            if records.len() == records.capacity() {
                let capacity = records
                    .capacity()
                    .saturating_mul(2)
                    .max(16)
                    .min(usize::try_from(limits.records).unwrap_or(usize::MAX));
                if capacity
                    .checked_mul(size_of::<Record<'_>>())
                    .ok_or(Reason::BuilderMemoryLimit)
                    .and_then(|bytes| storage.charge(bytes))
                    .is_err()
                    || records.try_reserve_exact(capacity - records.len()).is_err()
                {
                    failure = Some(Reason::BuilderMemoryLimit);
                    break;
                }
            }
            // S_ATTR_PURE_INSTRUCTIONS / S_ATTR_SOME_INSTRUCTIONS distinguish exact function
            // context from ordinary data symbols. Neither case permits nearest-symbol inference.
            let kind = if record.section.flags & (0x8000_0000 | 0x400) != 0 {
                RecordKind::Function
            } else {
                RecordKind::Symbol
            };
            records.push(Record {
                name: Cow::Borrowed(record.name),
                address: record.address,
                section: record.section,
                kind,
            });
        }
        statistics.inspected_symbols = symbols.inspected_symbols();
        if let Some(reason) = failure {
            return Self::terminal(identity, reason, statistics, storage.used);
        }
        // Accepted-record statistics describe raw nlist input, not derived ABI records. Metadata
        // adds searchable entries while carrying forward the raw pass's examined-name work budget.
        if let Err(reason) = crate::metadata::extract(
            object,
            context,
            limits,
            &mut storage,
            &mut records,
            symbols.examined_name_bytes(),
        ) {
            return Self::terminal(identity, reason, statistics, storage.used);
        }
        let mut bytes = header(identity, State::Complete, Reason::None, statistics)?;
        match encode(&mut bytes, records, limits, &mut storage) {
            Ok(()) => Ok(Self {
                bytes,
                state: State::Complete,
                reason: Reason::None,
                statistics,
                accounted_storage: storage.used,
            }),
            Err(reason) => Self::terminal(identity, reason, statistics, storage.used),
        }
    }

    /// Persist identity and failure diagnostics, discarding any accumulated searchable records.
    fn terminal(
        identity: Identity,
        reason: Reason,
        statistics: Statistics,
        accounted_storage: u64,
    ) -> Result<Self, BuildError> {
        let state = if reason == Reason::UnsupportedArchitecture {
            State::Unsupported
        } else {
            State::Incomplete
        };
        tracing::debug!(
            ?state,
            ?reason,
            ?statistics,
            "data-cache extraction produced no searchable tables"
        );
        Ok(Self {
            bytes: header(identity, state, reason, statistics)?,
            state,
            reason,
            statistics,
            accounted_storage,
        })
    }

    /// Writes canonical uncompressed bytes. A failed destination must not be published.
    pub fn serialize(&self, mut writer: impl Write) -> Result<(), BuildError> {
        writer.write_all(&self.bytes)?;
        Ok(())
    }
    /// Canonical uncompressed file, suitable for one-time validation before publication.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Extraction completeness.
    pub fn state(&self) -> State {
        self.state
    }
    /// Terminal reason, or [`Reason::None`].
    pub fn reason(&self) -> Reason {
        self.reason
    }
    /// Diagnostic counters before duplicate removal.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Conservative peak accounted builder-owned storage, including released construction tables.
    pub fn accounted_storage(&self) -> u64 {
        self.accounted_storage
    }
}
